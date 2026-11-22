#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Explicit five-state runtime enforcement capability model and observer-bound verification
//! contract (`crates/agent-guard/src/enforcement_state.rs`).
//!
//! Separates five distinct, non-collapsible security properties:
//! 1. `InstallState`      -- Expected `agent-guard` binary exists and passes integrity checks.
//! 2. `ConfigState`       -- Host integration config exists, is schema-valid, and pins the verified binary.
//! 3. `InvocationState`   -- Whether invocations are unobserved, self-reported diagnostics only, or observer-attested.
//! 4. `HostEnforcement`   -- Whether an independent observer verified that the host honored an authoritative denial
//!    and prevented the prohibited side effect for the exact runtime, workspace, config, and binary digest.
//! 5. `KernelEnforcement` -- Separate Landlock, seccomp-bpf, Seatbelt, and netns availability for mediated processes.
//!
//! Trust invariants:
//! - Stronger capabilities are never inferred from weaker ones (`Installed != Configured != Invoked != HostEnforced`).
//! - Local trace logs (`--trace-log`), `SessionLedger` counters, and hook-emitted witnesses are strictly
//!   `TrustLevel::SelfReportedDiagnostic`; they can never independently certify authentic host dispatch or
//!   `HostEnforcement::Verified`.
//! - Observational reads and witness writes ignore I/O failures so authoritative guard decisions never change.

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::{ZeroizingKey, constant_time_eq_bytes, hex_decode_32, hex_encode, sha256_hex};
use crate::exec_sandbox::{
    KernelSandboxMode, probe_host_sandbox_mode, probe_host_seccomp_verified,
};
use crate::json::JsonValue;
use crate::operator::detect_antigravity_workspace_dir;
use crate::resolve_repo_root;
use crate::traversal_ledger::{SessionLedger, session_ledger_path, state_base_dir};

type HmacSha256 = Hmac<Sha256>;

const MAX_CAPABILITY_RECORD_BYTES: u64 = 65_536;
const MAX_CONFIG_INSPECT_BYTES: u64 = 262_144;
const MAX_TRACE_INSPECT_BYTES: u64 = 262_144;
const CHALLENGE_TTL_SECS: u64 = 300;

/// Detected or explicitly specified host execution environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    LocalHost,
    AntigravityRemoteAgentsVm,
    UnsupportedHost(String),
}

impl ExecutionMode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::LocalHost => "local-host",
            Self::AntigravityRemoteAgentsVm => "antigravity-remote-agents-vm",
            Self::UnsupportedHost(label) => label.as_str(),
        }
    }

    pub fn supports_local_observer_verification(&self) -> bool {
        matches!(self, Self::LocalHost)
    }
}

/// Snapshot of runtime and OS kernel probes (live in CLI, deterministically injectable in tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSnapshot {
    pub execution_mode: ExecutionMode,
    pub kernel_fs_mode: KernelSandboxMode,
    pub seccomp_net: Option<bool>,
    pub netns_unshare: bool,
    pub binary_version_override: Option<String>,
}

impl ProbeSnapshot {
    pub fn probe_live(mode_override: Option<&str>) -> Result<Self, String> {
        let execution_mode = detect_execution_mode(mode_override)?;
        #[cfg(target_os = "linux")]
        let netns_unshare = crate::exec_sandbox::probe_linux_unshare_netns();
        #[cfg(not(target_os = "linux"))]
        let netns_unshare = false;
        Ok(Self {
            execution_mode,
            kernel_fs_mode: probe_host_sandbox_mode(),
            seccomp_net: probe_host_seccomp_verified(),
            netns_unshare,
            binary_version_override: None,
        })
    }

    pub fn effective_version(&self) -> &str {
        self.binary_version_override
            .as_deref()
            .unwrap_or(env!("CARGO_PKG_VERSION"))
    }
}

/// Detects the current execution environment from explicit CLI mode or non-sensitive VM markers.
pub fn detect_execution_mode(mode_override: Option<&str>) -> Result<ExecutionMode, String> {
    match mode_override.map(str::trim) {
        None | Some("") | Some("auto") => {
            if Path::new("/.vm/bin/vsock-ssh-listener").exists()
                && Path::new("/usr/local/bin/cmdlauncher").exists()
            {
                Ok(ExecutionMode::AntigravityRemoteAgentsVm)
            } else {
                Ok(ExecutionMode::LocalHost)
            }
        }
        Some("local") | Some("local-host") => Ok(ExecutionMode::LocalHost),
        Some("remote-agents") | Some("antigravity-remote-agents-vm") => {
            Ok(ExecutionMode::AntigravityRemoteAgentsVm)
        }
        Some("unsupported") | Some("unsupported-host") => Ok(ExecutionMode::UnsupportedHost(
            "unsupported-host".to_string(),
        )),
        Some(other) => Err(format!(
            "unsupported --execution-mode '{other}' (expected auto|local|remote-agents|unsupported)"
        )),
    }
}

/// Property 1: Executable installation and binary integrity state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallState {
    Verified {
        binary_path: String,
        version: String,
        binary_sha256: String,
    },
    Missing {
        expected_path: String,
        reason_code: &'static str,
    },
    IntegrityFailed {
        binary_path: String,
        reason_code: &'static str,
        detail: String,
    },
}

/// Property 2: Host integration configuration validity and binary pinning state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigState {
    Valid {
        adapter_id: String,
        config_rel_path: String,
        config_sha256: String,
        pinned_binary_matches: bool,
        protocol_compatible: bool,
    },
    Unconfigured {
        adapter_id: String,
        reason_code: &'static str,
    },
    Invalid {
        adapter_id: String,
        config_rel_path: Option<String>,
        reason_code: &'static str,
        detail: String,
    },
}

/// Origin of an invocation or enforcement evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    None,
    LocalSessionLedger,
    LocalTraceLog,
    HookDenialWitness,
    ObserverVerificationReceipt,
}

impl EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LocalSessionLedger => "local_session_ledger",
            Self::LocalTraceLog => "local_trace_log",
            Self::HookDenialWitness => "hook_denial_witness",
            Self::ObserverVerificationReceipt => "observer_verification_receipt",
        }
    }
}

/// Epistemic trust level of an invocation or enforcement record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    None,
    SelfReportedDiagnostic,
    ObserverVerified,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SelfReportedDiagnostic => "self_reported_diagnostic",
            Self::ObserverVerified => "observer_verified",
        }
    }
}

/// Property 3: Adapter invocation observation state (never implies host enforcement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationState {
    Verified {
        last_observed_ts_unix: u64,
        last_event: String,
        evidence_source: EvidenceSource,
        trust_level: TrustLevel,
    },
    DiagnosticOnly {
        last_observed_ts_unix: Option<u64>,
        last_event: Option<String>,
        observed_count: u64,
        evidence_source: EvidenceSource,
        trust_level: TrustLevel,
        reason_code: &'static str,
    },
    NoneObserved {
        reason_code: &'static str,
    },
}

/// Property 4: Host-side denial enforcement verification state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEnforcement {
    Verified {
        verified_at_unix: u64,
        challenge_id: String,
        evidence_source: EvidenceSource,
        trust_level: TrustLevel,
    },
    Unverified {
        reason_code: &'static str,
        detail: String,
    },
    NotVerifiedForExecutionMode {
        execution_mode: String,
        reason_code: &'static str,
        detail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockState {
    Enforced,
    PartiallyEnforced,
    Unavailable,
    NotApplicable,
}

impl LandlockState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::PartiallyEnforced => "partially_enforced",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompState {
    Verified,
    Unavailable,
    NotApplicable,
}

impl SeccompState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatbeltState {
    Enforced,
    Unavailable,
    NotApplicable,
}

impl SeatbeltState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Property 5: Independent OS kernel boundary availability for `exec-sandbox` child processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEnforcement {
    Full {
        landlock: LandlockState,
        seccomp: SeccompState,
        seatbelt: SeatbeltState,
        netns_unshare: bool,
    },
    Partial {
        landlock: LandlockState,
        seccomp: SeccompState,
        seatbelt: SeatbeltState,
        netns_unshare: bool,
        reason_code: &'static str,
        detail: String,
    },
    Unavailable {
        landlock: LandlockState,
        seccomp: SeccompState,
        seatbelt: SeatbeltState,
        netns_unshare: bool,
        reason_code: &'static str,
        detail: String,
    },
}

/// Explicit typed limitation entry explaining any unsupported, unverified, or stale capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLimitation {
    pub capability: &'static str,
    pub code: &'static str,
    pub detail: String,
}

/// Complete structured enforcement diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementReport {
    pub runtime_mode: String,
    pub os: &'static str,
    pub arch: &'static str,
    pub adapter_id: String,
    pub adapter_protocol: &'static str,
    pub protocol_compatible: bool,
    pub installed: InstallState,
    pub configured: ConfigState,
    pub invoked: InvocationState,
    pub host_enforced: HostEnforcement,
    pub kernel_enforced: KernelEnforcement,
    pub mandatory_protection_verified: bool,
    pub limitations: Vec<CapabilityLimitation>,
}

impl EnforcementReport {
    pub fn to_json_value(&self) -> JsonValue {
        let installed_json = match &self.installed {
            InstallState::Verified {
                binary_path,
                version,
                binary_sha256,
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("verified".to_string())),
                ("version".to_string(), JsonValue::Str(version.clone())),
                (
                    "binary_path".to_string(),
                    JsonValue::Str(binary_path.clone()),
                ),
                (
                    "binary_sha256".to_string(),
                    JsonValue::Str(binary_sha256.clone()),
                ),
                ("reason_code".to_string(), JsonValue::Null),
            ]),
            InstallState::Missing {
                expected_path,
                reason_code,
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("missing".to_string())),
                ("version".to_string(), JsonValue::Null),
                (
                    "binary_path".to_string(),
                    JsonValue::Str(expected_path.clone()),
                ),
                ("binary_sha256".to_string(), JsonValue::Null),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
            ]),
            InstallState::IntegrityFailed {
                binary_path,
                reason_code,
                detail,
            } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("integrity_failed".to_string()),
                ),
                ("version".to_string(), JsonValue::Null),
                (
                    "binary_path".to_string(),
                    JsonValue::Str(binary_path.clone()),
                ),
                ("binary_sha256".to_string(), JsonValue::Null),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
                ("detail".to_string(), JsonValue::Str(detail.clone())),
            ]),
        };

        let configured_json = match &self.configured {
            ConfigState::Valid {
                config_rel_path,
                config_sha256,
                pinned_binary_matches,
                protocol_compatible,
                ..
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("valid".to_string())),
                (
                    "config_rel_path".to_string(),
                    JsonValue::Str(config_rel_path.clone()),
                ),
                (
                    "config_sha256".to_string(),
                    JsonValue::Str(config_sha256.clone()),
                ),
                (
                    "pinned_binary_matches".to_string(),
                    JsonValue::Bool(*pinned_binary_matches),
                ),
                (
                    "protocol_compatible".to_string(),
                    JsonValue::Bool(*protocol_compatible),
                ),
                ("reason_code".to_string(), JsonValue::Null),
            ]),
            ConfigState::Unconfigured { reason_code, .. } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("unconfigured".to_string()),
                ),
                ("config_rel_path".to_string(), JsonValue::Null),
                ("config_sha256".to_string(), JsonValue::Null),
                ("pinned_binary_matches".to_string(), JsonValue::Bool(false)),
                ("protocol_compatible".to_string(), JsonValue::Bool(false)),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
            ]),
            ConfigState::Invalid {
                config_rel_path,
                reason_code,
                detail,
                ..
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("invalid".to_string())),
                (
                    "config_rel_path".to_string(),
                    match config_rel_path {
                        Some(p) => JsonValue::Str(p.clone()),
                        None => JsonValue::Null,
                    },
                ),
                ("config_sha256".to_string(), JsonValue::Null),
                ("pinned_binary_matches".to_string(), JsonValue::Bool(false)),
                ("protocol_compatible".to_string(), JsonValue::Bool(false)),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
                ("detail".to_string(), JsonValue::Str(detail.clone())),
            ]),
        };

        let invoked_json = match &self.invoked {
            InvocationState::Verified {
                last_observed_ts_unix,
                last_event,
                evidence_source,
                trust_level,
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("verified".to_string())),
                (
                    "last_observed_ts_unix".to_string(),
                    JsonValue::Uint(*last_observed_ts_unix),
                ),
                ("last_event".to_string(), JsonValue::Str(last_event.clone())),
                (
                    "evidence_source".to_string(),
                    JsonValue::Str(evidence_source.as_str().to_string()),
                ),
                (
                    "trust_level".to_string(),
                    JsonValue::Str(trust_level.as_str().to_string()),
                ),
                ("reason_code".to_string(), JsonValue::Null),
            ]),
            InvocationState::DiagnosticOnly {
                last_observed_ts_unix,
                last_event,
                observed_count,
                evidence_source,
                trust_level,
                reason_code,
            } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("diagnostic_only".to_string()),
                ),
                (
                    "last_observed_ts_unix".to_string(),
                    match last_observed_ts_unix {
                        Some(ts) => JsonValue::Uint(*ts),
                        None => JsonValue::Null,
                    },
                ),
                (
                    "last_event".to_string(),
                    match last_event {
                        Some(ev) => JsonValue::Str(ev.clone()),
                        None => JsonValue::Null,
                    },
                ),
                (
                    "observed_count".to_string(),
                    JsonValue::Uint(*observed_count),
                ),
                (
                    "evidence_source".to_string(),
                    JsonValue::Str(evidence_source.as_str().to_string()),
                ),
                (
                    "trust_level".to_string(),
                    JsonValue::Str(trust_level.as_str().to_string()),
                ),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
            ]),
            InvocationState::NoneObserved { reason_code } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("none_observed".to_string()),
                ),
                ("last_observed_ts_unix".to_string(), JsonValue::Null),
                ("last_event".to_string(), JsonValue::Null),
                (
                    "evidence_source".to_string(),
                    JsonValue::Str(EvidenceSource::None.as_str().to_string()),
                ),
                (
                    "trust_level".to_string(),
                    JsonValue::Str(TrustLevel::None.as_str().to_string()),
                ),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
            ]),
        };

        let host_json = match &self.host_enforced {
            HostEnforcement::Verified {
                verified_at_unix,
                challenge_id,
                evidence_source,
                trust_level,
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("verified".to_string())),
                (
                    "verified_at_unix".to_string(),
                    JsonValue::Uint(*verified_at_unix),
                ),
                (
                    "challenge_id".to_string(),
                    JsonValue::Str(challenge_id.clone()),
                ),
                (
                    "evidence_source".to_string(),
                    JsonValue::Str(evidence_source.as_str().to_string()),
                ),
                (
                    "trust_level".to_string(),
                    JsonValue::Str(trust_level.as_str().to_string()),
                ),
                ("reason_code".to_string(), JsonValue::Null),
            ]),
            HostEnforcement::Unverified {
                reason_code,
                detail,
            } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("unverified".to_string()),
                ),
                ("verified_at_unix".to_string(), JsonValue::Null),
                (
                    "evidence_source".to_string(),
                    JsonValue::Str(EvidenceSource::None.as_str().to_string()),
                ),
                (
                    "trust_level".to_string(),
                    JsonValue::Str(TrustLevel::None.as_str().to_string()),
                ),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
                ("detail".to_string(), JsonValue::Str(detail.clone())),
            ]),
            HostEnforcement::NotVerifiedForExecutionMode {
                execution_mode,
                reason_code,
                detail,
            } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("not_verified_for_execution_mode".to_string()),
                ),
                ("verified_at_unix".to_string(), JsonValue::Null),
                (
                    "execution_mode".to_string(),
                    JsonValue::Str(execution_mode.clone()),
                ),
                (
                    "evidence_source".to_string(),
                    JsonValue::Str(EvidenceSource::None.as_str().to_string()),
                ),
                (
                    "trust_level".to_string(),
                    JsonValue::Str(TrustLevel::None.as_str().to_string()),
                ),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
                ("detail".to_string(), JsonValue::Str(detail.clone())),
            ]),
        };

        let kernel_json = match &self.kernel_enforced {
            KernelEnforcement::Full {
                landlock,
                seccomp,
                seatbelt,
                netns_unshare,
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("full".to_string())),
                (
                    "landlock".to_string(),
                    JsonValue::Str(landlock.as_str().to_string()),
                ),
                (
                    "seccomp".to_string(),
                    JsonValue::Str(seccomp.as_str().to_string()),
                ),
                (
                    "seatbelt".to_string(),
                    JsonValue::Str(seatbelt.as_str().to_string()),
                ),
                ("netns_unshare".to_string(), JsonValue::Bool(*netns_unshare)),
                (
                    "applies_only_when_mediated".to_string(),
                    JsonValue::Bool(true),
                ),
                ("reason_code".to_string(), JsonValue::Null),
            ]),
            KernelEnforcement::Partial {
                landlock,
                seccomp,
                seatbelt,
                netns_unshare,
                reason_code,
                detail,
            } => JsonValue::Object(vec![
                ("state".to_string(), JsonValue::Str("partial".to_string())),
                (
                    "landlock".to_string(),
                    JsonValue::Str(landlock.as_str().to_string()),
                ),
                (
                    "seccomp".to_string(),
                    JsonValue::Str(seccomp.as_str().to_string()),
                ),
                (
                    "seatbelt".to_string(),
                    JsonValue::Str(seatbelt.as_str().to_string()),
                ),
                ("netns_unshare".to_string(), JsonValue::Bool(*netns_unshare)),
                (
                    "applies_only_when_mediated".to_string(),
                    JsonValue::Bool(true),
                ),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
                ("detail".to_string(), JsonValue::Str(detail.clone())),
            ]),
            KernelEnforcement::Unavailable {
                landlock,
                seccomp,
                seatbelt,
                netns_unshare,
                reason_code,
                detail,
            } => JsonValue::Object(vec![
                (
                    "state".to_string(),
                    JsonValue::Str("unavailable".to_string()),
                ),
                (
                    "landlock".to_string(),
                    JsonValue::Str(landlock.as_str().to_string()),
                ),
                (
                    "seccomp".to_string(),
                    JsonValue::Str(seccomp.as_str().to_string()),
                ),
                (
                    "seatbelt".to_string(),
                    JsonValue::Str(seatbelt.as_str().to_string()),
                ),
                ("netns_unshare".to_string(), JsonValue::Bool(*netns_unshare)),
                (
                    "applies_only_when_mediated".to_string(),
                    JsonValue::Bool(true),
                ),
                (
                    "reason_code".to_string(),
                    JsonValue::Str((*reason_code).to_string()),
                ),
                ("detail".to_string(), JsonValue::Str(detail.clone())),
            ]),
        };

        let limits_json: Vec<JsonValue> = self
            .limitations
            .iter()
            .map(|l| {
                JsonValue::Object(vec![
                    (
                        "capability".to_string(),
                        JsonValue::Str(l.capability.to_string()),
                    ),
                    ("code".to_string(), JsonValue::Str(l.code.to_string())),
                    ("detail".to_string(), JsonValue::Str(l.detail.clone())),
                ])
            })
            .collect();

        JsonValue::Object(vec![
            (
                "schema".to_string(),
                JsonValue::Str("dotagent.enforcement_status.v1".to_string()),
            ),
            (
                "runtime".to_string(),
                JsonValue::Object(vec![
                    (
                        "execution_mode".to_string(),
                        JsonValue::Str(self.runtime_mode.clone()),
                    ),
                    ("os".to_string(), JsonValue::Str(self.os.to_string())),
                    ("arch".to_string(), JsonValue::Str(self.arch.to_string())),
                ]),
            ),
            (
                "adapter".to_string(),
                JsonValue::Object(vec![
                    ("id".to_string(), JsonValue::Str(self.adapter_id.clone())),
                    (
                        "protocol".to_string(),
                        JsonValue::Str(self.adapter_protocol.to_string()),
                    ),
                    (
                        "protocol_compatible".to_string(),
                        JsonValue::Bool(self.protocol_compatible),
                    ),
                    (
                        "post_tool_use_mode".to_string(),
                        JsonValue::Str("observational_only".to_string()),
                    ),
                ]),
            ),
            ("installed".to_string(), installed_json),
            ("configured".to_string(), configured_json),
            ("invoked".to_string(), invoked_json),
            ("host_enforced".to_string(), host_json),
            ("kernel_enforced".to_string(), kernel_json),
            (
                "mandatory_protection_verified".to_string(),
                JsonValue::Bool(self.mandatory_protection_verified),
            ),
            ("limitations".to_string(), JsonValue::Array(limits_json)),
        ])
    }

    pub fn format_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "dotagent enforcement status (adapter='{}', mode='{}', os='{}/{}')\n",
            self.adapter_id, self.runtime_mode, self.os, self.arch
        ));
        match &self.installed {
            InstallState::Verified {
                version,
                binary_sha256,
                binary_path,
            } => out.push_str(&format!(
                "  1. Installed:       VERIFIED (v{version}, sha256={}, bin='{binary_path}')\n",
                &binary_sha256[..16]
            )),
            InstallState::Missing {
                expected_path,
                reason_code,
            } => out.push_str(&format!(
                "  1. Installed:       MISSING [{reason_code}] (expected '{expected_path}')\n"
            )),
            InstallState::IntegrityFailed {
                reason_code,
                detail,
                ..
            } => out.push_str(&format!(
                "  1. Installed:       INTEGRITY_FAILED [{reason_code}] ({detail})\n"
            )),
        }
        match &self.configured {
            ConfigState::Valid {
                config_rel_path,
                config_sha256,
                ..
            } => out.push_str(&format!(
                "  2. Configured:      VALID (path='{config_rel_path}', sha256={}, protocol_compatible=true, pinned_binary_matches=true)\n",
                &config_sha256[..16]
            )),
            ConfigState::Unconfigured { reason_code, .. } => out.push_str(&format!(
                "  2. Configured:      UNCONFIGURED [{reason_code}]\n"
            )),
            ConfigState::Invalid {
                reason_code,
                detail,
                ..
            } => out.push_str(&format!(
                "  2. Configured:      INVALID [{reason_code}] ({detail})\n"
            )),
        }
        match &self.invoked {
            InvocationState::Verified {
                last_observed_ts_unix,
                last_event,
                evidence_source,
                trust_level,
            } => out.push_str(&format!(
                "  3. Invoked:         VERIFIED (event='{last_event}', ts={last_observed_ts_unix}, source={}, trust={})\n",
                evidence_source.as_str(),
                trust_level.as_str()
            )),
            InvocationState::DiagnosticOnly {
                observed_count,
                evidence_source,
                trust_level,
                reason_code,
                ..
            } => out.push_str(&format!(
                "  3. Invoked:         DIAGNOSTIC_ONLY [{reason_code}] (count={observed_count}, source={}, trust={})\n",
                evidence_source.as_str(),
                trust_level.as_str()
            )),
            InvocationState::NoneObserved { reason_code } => out.push_str(&format!(
                "  3. Invoked:         NONE_OBSERVED [{reason_code}]\n"
            )),
        }
        match &self.host_enforced {
            HostEnforcement::Verified {
                verified_at_unix,
                challenge_id,
                ..
            } => out.push_str(&format!(
                "  4. Host-enforced:   VERIFIED (challenge='{challenge_id}', ts={verified_at_unix}, trust=observer_verified)\n"
            )),
            HostEnforcement::Unverified {
                reason_code,
                detail,
            } => out.push_str(&format!(
                "  4. Host-enforced:   UNVERIFIED [{reason_code}] ({detail})\n"
            )),
            HostEnforcement::NotVerifiedForExecutionMode {
                execution_mode,
                reason_code,
                detail,
            } => out.push_str(&format!(
                "  4. Host-enforced:   NOT_VERIFIED_FOR_EXECUTION_MODE [{reason_code}] (mode='{execution_mode}': {detail})\n"
            )),
        }
        match &self.kernel_enforced {
            KernelEnforcement::Full {
                landlock,
                seccomp,
                seatbelt,
                netns_unshare,
            } => out.push_str(&format!(
                "  5. Kernel-enforced: FULL (landlock={}, seccomp={}, seatbelt={}, netns_unshare={netns_unshare}; mediated-processes-only)\n",
                landlock.as_str(),
                seccomp.as_str(),
                seatbelt.as_str()
            )),
            KernelEnforcement::Partial {
                landlock,
                seccomp,
                seatbelt,
                netns_unshare,
                reason_code,
                ..
            } => out.push_str(&format!(
                "  5. Kernel-enforced: PARTIAL [{reason_code}] (landlock={}, seccomp={}, seatbelt={}, netns_unshare={netns_unshare}; mediated-processes-only)\n",
                landlock.as_str(),
                seccomp.as_str(),
                seatbelt.as_str()
            )),
            KernelEnforcement::Unavailable {
                landlock,
                seccomp,
                seatbelt,
                reason_code,
                ..
            } => out.push_str(&format!(
                "  5. Kernel-enforced: UNAVAILABLE [{reason_code}] (landlock={}, seccomp={}, seatbelt={})\n",
                landlock.as_str(),
                seccomp.as_str(),
                seatbelt.as_str()
            )),
        }
        out.push_str(&format!(
            "Mandatory runtime protection verified: {}\n",
            self.mandatory_protection_verified
        ));
        out
    }
}

/// Phase 4 verification contract error with stable reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub code: &'static str,
    pub detail: String,
}

impl ContractError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Issued Phase 4 challenge awaiting controlled host hook denial and independent side-effect check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationChallenge {
    pub challenge_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub adapter_id: String,
    pub execution_mode: String,
    pub workspace_sha256: String,
    pub config_sha256: String,
    pub binary_version: String,
    pub binary_sha256: String,
    pub canary_rel_path: String,
}

/// Verified Phase 4 receipt bound to exact runtime, workspace, config, and binary digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReceipt {
    pub challenge_id: String,
    pub verified_at_unix: u64,
    pub adapter_id: String,
    pub execution_mode: String,
    pub workspace_sha256: String,
    pub config_sha256: String,
    pub binary_version: String,
    pub binary_sha256: String,
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn enforcement_state_dir() -> Result<PathBuf, ContractError> {
    let base = state_base_dir();
    if let Ok(m) = fs::symlink_metadata(&base)
        && m.file_type().is_symlink()
    {
        return Err(ContractError::new(
            "STATE_DIR_SYMLINK",
            "agent-guard state directory must not be a symlink",
        ));
    }
    let dir = base.join("enforcement");
    if let Ok(m) = fs::symlink_metadata(&dir) {
        if m.file_type().is_symlink() || !m.file_type().is_dir() {
            return Err(ContractError::new(
                "STATE_DIR_INVALID",
                "enforcement state path is not a regular directory",
            ));
        }
    } else {
        fs::create_dir_all(&dir).map_err(|e| {
            ContractError::new(
                "STATE_DIR_IO_ERROR",
                format!("failed creating enforcement state directory: {e}"),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir)
}

fn load_or_create_verify_key(dir: &Path) -> Result<ZeroizingKey, ContractError> {
    let key_path = dir.join("verify_host.key");
    if let Ok(meta) = fs::symlink_metadata(&key_path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(ContractError::new(
                "VERIFY_KEY_INVALID",
                "verify_host.key must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if (meta.permissions().mode() & 0o077) != 0 {
                return Err(ContractError::new(
                    "VERIFY_KEY_UNSAFE_MODE",
                    "verify_host.key must have 0600 permissions",
                ));
            }
        }
        let raw = fs::read(&key_path).map_err(|e| {
            ContractError::new("VERIFY_KEY_IO_ERROR", format!("read verify_host.key: {e}"))
        })?;
        if raw.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            return Ok(ZeroizingKey::new(arr));
        }
        return Err(ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "verify_host.key has invalid byte length",
        ));
    }

    let mut raw_key = [0u8; 32];
    let mut urandom = fs::File::open("/dev/urandom")
        .map_err(|e| ContractError::new("ENTROPY_IO_ERROR", format!("open /dev/urandom: {e}")))?;
    urandom
        .read_exact(&mut raw_key)
        .map_err(|e| ContractError::new("ENTROPY_IO_ERROR", format!("read /dev/urandom: {e}")))?;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(&key_path) {
        Ok(mut f) => {
            f.write_all(&raw_key).map_err(|e| {
                ContractError::new("VERIFY_KEY_IO_ERROR", format!("write verify_host.key: {e}"))
            })?;
            Ok(ZeroizingKey::new(raw_key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let reread = fs::read(&key_path).map_err(|re| {
                ContractError::new("VERIFY_KEY_IO_ERROR", format!("read verify_host.key: {re}"))
            })?;
            if reread.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&reread);
                Ok(ZeroizingKey::new(arr))
            } else {
                Err(ContractError::new(
                    "MALFORMED_CAPABILITY_RECORD",
                    "corrupt verify_host.key",
                ))
            }
        }
        Err(e) => Err(ContractError::new(
            "VERIFY_KEY_IO_ERROR",
            format!("create verify_host.key: {e}"),
        )),
    }
}

fn load_existing_verify_key(dir: &Path) -> Result<Option<ZeroizingKey>, &'static str> {
    let key_path = dir.join("verify_host.key");
    let meta = match fs::symlink_metadata(&key_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("VERIFY_KEY_IO_ERROR"),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err("MALFORMED_CAPABILITY_RECORD");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o077) != 0 {
            return Err("FORGED_EVIDENCE_REJECTED");
        }
    }
    let Ok(raw) = fs::read(&key_path) else {
        return Err("VERIFY_KEY_IO_ERROR");
    };
    if raw.len() != 32 {
        return Err("MALFORMED_CAPABILITY_RECORD");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(Some(ZeroizingKey::new(arr)))
}

fn compute_hmac_tag(key: &ZeroizingKey, domain: &[u8], fields: &[&str]) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key.as_bytes()) else {
        return [0u8; 32];
    };
    mac.update(domain);
    mac.update(&[0u8]);
    for f in fields {
        mac.update(&(f.len() as u64).to_be_bytes());
        mac.update(f.as_bytes());
        mac.update(&[0u8]);
    }
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn canonical_workspace_digest(workspace: &Path) -> (PathBuf, String) {
    let canon = fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let digest = sha256_hex(canon.to_string_lossy().as_bytes());
    (canon, digest)
}

fn slot_prefix_for(workspace: &Path, adapter_id: &str) -> String {
    let (_, ws_sha) = canonical_workspace_digest(workspace);
    let clean_adapter: String = adapter_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    format!("{}_{}", &ws_sha[..24], clean_adapter)
}

fn adapter_protocol_name(adapter_id: &str) -> &'static str {
    match adapter_id {
        "antigravity" => "antigravity-hooks-v1",
        "gemini" => "gemini-settings-hooks-v1",
        "claude" => "claude-settings-hooks-v1",
        "cursor" => "cursor-hooks-v1",
        "codex" => "codex-mcp-and-sandbox-v1",
        _ => "unknown",
    }
}

/// Evaluates Property 1 (`InstallState`) without inferring configuration or active mediation.
pub fn evaluate_install_state(bin_dir: &Path, version_str: &str) -> InstallState {
    let expected = bin_dir.join("agent-guard");
    let meta = match fs::symlink_metadata(&expected) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return InstallState::Missing {
                expected_path: expected.display().to_string(),
                reason_code: "BINARY_MISSING",
            };
        }
        Err(e) => {
            return InstallState::IntegrityFailed {
                binary_path: expected.display().to_string(),
                reason_code: "BINARY_STAT_FAILED",
                detail: format!("cannot stat '{}': {e}", expected.display()),
            };
        }
    };
    if meta.file_type().is_symlink() {
        return InstallState::IntegrityFailed {
            binary_path: expected.display().to_string(),
            reason_code: "BINARY_SYMLINK_REJECTED",
            detail: "agent-guard executable path must not be a symlink".to_string(),
        };
    }
    if !meta.file_type().is_file() {
        return InstallState::IntegrityFailed {
            binary_path: expected.display().to_string(),
            reason_code: "BINARY_NOT_REGULAR_FILE",
            detail: "agent-guard executable path is not a regular file".to_string(),
        };
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if (mode & 0o111) == 0 {
            return InstallState::IntegrityFailed {
                binary_path: expected.display().to_string(),
                reason_code: "BINARY_NOT_EXECUTABLE",
                detail: "agent-guard file lacks executable permission bits".to_string(),
            };
        }
        if (mode & 0o002) != 0 {
            return InstallState::IntegrityFailed {
                binary_path: expected.display().to_string(),
                reason_code: "BINARY_WORLD_WRITABLE",
                detail: "agent-guard file must not be world-writable".to_string(),
            };
        }
    }
    let canon = match fs::canonicalize(&expected) {
        Ok(c) => c,
        Err(e) => {
            return InstallState::IntegrityFailed {
                binary_path: expected.display().to_string(),
                reason_code: "BINARY_CANONICALIZE_FAILED",
                detail: format!("failed canonicalizing binary: {e}"),
            };
        }
    };
    let bytes = match fs::read(&canon) {
        Ok(b) => b,
        Err(e) => {
            return InstallState::IntegrityFailed {
                binary_path: canon.display().to_string(),
                reason_code: "BINARY_HASH_READ_FAILED",
                detail: format!("failed reading binary for SHA-256 verification: {e}"),
            };
        }
    };
    if bytes.is_empty() {
        return InstallState::IntegrityFailed {
            binary_path: canon.display().to_string(),
            reason_code: "BINARY_EMPTY",
            detail: "agent-guard binary is 0 bytes".to_string(),
        };
    }
    let digest = sha256_hex(&bytes);
    InstallState::Verified {
        binary_path: canon.display().to_string(),
        version: version_str.to_string(),
        binary_sha256: digest,
    }
}

fn validate_antigravity_command_list(
    hooks_arr: &[JsonValue],
    expected_event: &str,
    verified_bin_canon: Option<&Path>,
) -> Result<bool, (&'static str, String)> {
    if hooks_arr.is_empty() {
        return Err((
            "CONFIG_PROTOCOL_INCOMPATIBLE",
            format!("Antigravity '{expected_event}' hook list must not be empty"),
        ));
    }
    let mut all_bins_match = verified_bin_canon.is_some();
    for item in hooks_arr {
        let Some(obj) = item.as_object() else {
            return Err((
                "CONFIG_PROTOCOL_INCOMPATIBLE",
                format!("Antigravity '{expected_event}' entry must be an object"),
            ));
        };
        let ty = obj
            .iter()
            .find(|(k, _)| k == "type")
            .and_then(|(_, v)| v.as_str());
        if ty != Some("command") {
            return Err((
                "CONFIG_PROTOCOL_INCOMPATIBLE",
                format!("Antigravity '{expected_event}' hook must have \"type\": \"command\""),
            ));
        }
        let Some(cmd) = obj
            .iter()
            .find(|(k, _)| k == "command")
            .and_then(|(_, v)| v.as_str())
        else {
            return Err((
                "CONFIG_PROTOCOL_INCOMPATIBLE",
                format!("Antigravity '{expected_event}' hook missing string 'command'"),
            ));
        };
        let tokens = tokenize_antigravity_hook_command(cmd)?;
        if tokens.len() < 3
            || tokens[1] != "antigravity-hook"
            || tokens[2].as_str() != expected_event
        {
            return Err((
                "CONFIG_PROTOCOL_INCOMPATIBLE",
                format!(
                    "Antigravity '{expected_event}' command must invoke exact 'antigravity-hook {expected_event}'"
                ),
            ));
        }
        let mut idx = 3usize;
        let mut seen_ws = false;
        let mut seen_trace = false;
        while idx < tokens.len() {
            let flag = tokens[idx].as_str();
            let Some(val) = tokens.get(idx + 1) else {
                return Err((
                    "CONFIG_PROTOCOL_INCOMPATIBLE",
                    format!(
                        "Antigravity '{expected_event}' command flag '{flag}' is missing its path argument"
                    ),
                ));
            };
            match flag {
                "--workspace" if !seen_ws => {
                    seen_ws = true;
                    if !Path::new(val).is_absolute() {
                        return Err((
                            "CONFIG_PROTOCOL_INCOMPATIBLE",
                            format!(
                                "Antigravity '{expected_event}' --workspace argument must be an absolute path"
                            ),
                        ));
                    }
                }
                "--trace-log" if !seen_trace => {
                    seen_trace = true;
                    if !Path::new(val).is_absolute() {
                        return Err((
                            "CONFIG_PROTOCOL_INCOMPATIBLE",
                            format!(
                                "Antigravity '{expected_event}' --trace-log argument must be an absolute path"
                            ),
                        ));
                    }
                }
                _ => {
                    return Err((
                        "CONFIG_PROTOCOL_INCOMPATIBLE",
                        format!(
                            "Antigravity '{expected_event}' command contains unsupported or duplicate flag '{flag}'"
                        ),
                    ));
                }
            }
            idx += 2;
        }

        let first_path = Path::new(&tokens[0]);
        if !first_path.is_absolute() {
            all_bins_match = false;
        } else if let Some(exp_bin) = verified_bin_canon {
            let tok_canon = fs::canonicalize(first_path).ok();
            if tok_canon.as_deref() != Some(exp_bin) {
                all_bins_match = false;
            }
        }
    }
    Ok(all_bins_match)
}

fn tokenize_antigravity_hook_command(cmd: &str) -> Result<Vec<String>, (&'static str, String)> {
    if cmd.trim().is_empty() || cmd.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err((
            "CONFIG_PROTOCOL_INCOMPATIBLE",
            "Antigravity hook command is empty or contains control characters".to_string(),
        ));
    }
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut in_single = false;
    for ch in cmd.chars() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur.push(ch);
            }
        } else if ch == '\'' {
            in_single = true;
            in_token = true;
        } else if ch == ' ' || ch == '\t' {
            if in_token {
                tokens.push(std::mem::take(&mut cur));
                in_token = false;
            }
        } else if matches!(
            ch,
            ';' | '|' | '&' | '`' | '$' | '<' | '>' | '(' | ')' | '\\' | '"'
        ) {
            return Err((
                "CONFIG_PROTOCOL_INCOMPATIBLE",
                format!("Antigravity hook command contains disallowed shell metacharacter '{ch}'"),
            ));
        } else {
            cur.push(ch);
            in_token = true;
        }
    }
    if in_single {
        return Err((
            "CONFIG_PROTOCOL_INCOMPATIBLE",
            "Antigravity hook command has an unclosed single quote".to_string(),
        ));
    }
    if in_token {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Evaluates Property 2 (`ConfigState`) without inferring runtime invocation or enforcement.
pub fn evaluate_config_state(
    workspace: &Path,
    adapter_id: &str,
    install_state: &InstallState,
) -> ConfigState {
    let verified_bin_canon: Option<PathBuf> = match install_state {
        InstallState::Verified { binary_path, .. } => Some(PathBuf::from(binary_path)),
        _ => None,
    };

    match adapter_id {
        "antigravity" => {
            let ag_dir = match detect_antigravity_workspace_dir(workspace) {
                Ok(d) => d,
                Err(detail) => {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: None,
                        reason_code: "CONFIG_LAYOUT_INVALID",
                        detail,
                    };
                }
            };
            let hooks_path = ag_dir.join("hooks.json");
            let rel_display = hooks_path
                .strip_prefix(workspace)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| ".agents/hooks.json".to_string());

            let meta = match fs::symlink_metadata(&hooks_path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return ConfigState::Unconfigured {
                        adapter_id: adapter_id.to_string(),
                        reason_code: "INTEGRATION_UNCONFIGURED",
                    };
                }
                Err(e) => {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_display),
                        reason_code: "CONFIG_READ_ERROR",
                        detail: format!("cannot stat hooks.json: {e}"),
                    };
                }
            };
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_SYMLINK_OR_OBJECT_INVALID",
                    detail: "hooks.json must be a non-symlink regular file".to_string(),
                };
            }
            if meta.len() > MAX_CONFIG_INSPECT_BYTES {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_OVERSIZED",
                    detail: "hooks.json exceeds 256 KiB bound".to_string(),
                };
            }
            let raw_bytes = match fs::read(&hooks_path) {
                Ok(b) => b,
                Err(e) => {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_display),
                        reason_code: "CONFIG_READ_ERROR",
                        detail: format!("failed reading hooks.json: {e}"),
                    };
                }
            };
            let config_sha256 = sha256_hex(&raw_bytes);
            let Ok(raw_str) = std::str::from_utf8(&raw_bytes) else {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_NON_UTF8",
                    detail: "hooks.json contains invalid UTF-8".to_string(),
                };
            };
            let parsed = match JsonValue::parse(raw_str) {
                Ok(v) => v,
                Err(e) => {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_display),
                        reason_code: "CONFIG_MALFORMED_JSON",
                        detail: format!("malformed hooks.json: {e}"),
                    };
                }
            };
            if parsed.as_object().is_none() {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
                    detail: "hooks.json root must be a JSON object".to_string(),
                };
            }
            if parsed.get("hooks").is_some()
                || parsed.get("BeforeTool").is_some()
                || parsed.get("AfterTool").is_some()
            {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
                    detail: "hooks.json uses Gemini/Claude schema instead of native Antigravity named hook groups".to_string(),
                };
            }
            let Some(dg) = parsed.get("dotagent-guard") else {
                return ConfigState::Unconfigured {
                    adapter_id: adapter_id.to_string(),
                    reason_code: "INTEGRATION_UNCONFIGURED",
                };
            };
            if dg.as_object().is_none() {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
                    detail: "'dotagent-guard' entry must be a JSON object".to_string(),
                };
            }
            if dg.get("enabled").and_then(JsonValue::as_bool) == Some(false) {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_HOOKS_DISABLED",
                    detail: "'dotagent-guard.enabled' is false".to_string(),
                };
            }

            let mut all_bins_match = verified_bin_canon.is_some();
            for tool_ev in ["PreToolUse", "PostToolUse"] {
                let Some(tool_matchers) = dg.get(tool_ev).and_then(JsonValue::as_array) else {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_display),
                        reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
                        detail: format!(
                            "missing required 'dotagent-guard.{tool_ev}' matcher array"
                        ),
                    };
                };
                let mut has_wildcard_matcher = false;
                for m in tool_matchers {
                    let matcher_str = m.get("matcher").and_then(JsonValue::as_str).unwrap_or("");
                    if matcher_str == "*" {
                        has_wildcard_matcher = true;
                    }
                    let Some(inner_hooks) = m.get("hooks").and_then(JsonValue::as_array) else {
                        return ConfigState::Invalid {
                            adapter_id: adapter_id.to_string(),
                            config_rel_path: Some(rel_display),
                            reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
                            detail: format!("{tool_ev} matcher entry missing 'hooks' array"),
                        };
                    };
                    match validate_antigravity_command_list(
                        inner_hooks,
                        tool_ev,
                        verified_bin_canon.as_deref(),
                    ) {
                        Ok(matched) => all_bins_match &= matched,
                        Err((code, detail)) => {
                            return ConfigState::Invalid {
                                adapter_id: adapter_id.to_string(),
                                config_rel_path: Some(rel_display),
                                reason_code: code,
                                detail,
                            };
                        }
                    }
                }
                if !has_wildcard_matcher {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_display),
                        reason_code: "CONFIG_INCOMPLETE_MATCHER",
                        detail: format!("{tool_ev} must register wildcard matcher '*'"),
                    };
                }
            }

            for direct_ev in ["SessionStart", "PreInvocation", "PostInvocation", "Stop"] {
                let Some(arr) = dg.get(direct_ev).and_then(JsonValue::as_array) else {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_display),
                        reason_code: "CONFIG_PROTOCOL_INCOMPATIBLE",
                        detail: format!("missing required 'dotagent-guard.{direct_ev}' hook array"),
                    };
                };
                match validate_antigravity_command_list(
                    arr,
                    direct_ev,
                    verified_bin_canon.as_deref(),
                ) {
                    Ok(matched) => all_bins_match &= matched,
                    Err((code, detail)) => {
                        return ConfigState::Invalid {
                            adapter_id: adapter_id.to_string(),
                            config_rel_path: Some(rel_display),
                            reason_code: code,
                            detail,
                        };
                    }
                }
            }

            if !all_bins_match {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_display),
                    reason_code: "CONFIG_BINARY_MISMATCH",
                    detail: "hooks.json command does not pin the verified agent-guard executable"
                        .to_string(),
                };
            }

            ConfigState::Valid {
                adapter_id: adapter_id.to_string(),
                config_rel_path: rel_display,
                config_sha256,
                pinned_binary_matches: true,
                protocol_compatible: true,
            }
        }
        "claude" | "cursor" | "codex" | "gemini" => {
            let (cfg_path, rel_label) = match adapter_id {
                "claude" => (
                    workspace.join(".claude/settings.json"),
                    ".claude/settings.json".to_string(),
                ),
                "cursor" => (
                    workspace.join(".cursor/hooks.json"),
                    ".cursor/hooks.json".to_string(),
                ),
                "codex" => (
                    workspace.join(".codex/config.toml"),
                    ".codex/config.toml".to_string(),
                ),
                _ => {
                    let p = std::env::var("HOME")
                        .map(|h| PathBuf::from(h).join(".gemini/settings.json"))
                        .unwrap_or_else(|_| PathBuf::from(".gemini/settings.json"));
                    (p, "~/.gemini/settings.json".to_string())
                }
            };
            let meta = match fs::symlink_metadata(&cfg_path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return ConfigState::Unconfigured {
                        adapter_id: adapter_id.to_string(),
                        reason_code: "INTEGRATION_UNCONFIGURED",
                    };
                }
                Err(e) => {
                    return ConfigState::Invalid {
                        adapter_id: adapter_id.to_string(),
                        config_rel_path: Some(rel_label),
                        reason_code: "CONFIG_READ_ERROR",
                        detail: format!("cannot stat config: {e}"),
                    };
                }
            };
            if meta.file_type().is_symlink()
                || !meta.file_type().is_file()
                || meta.len() > MAX_CONFIG_INSPECT_BYTES
            {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_label),
                    reason_code: "CONFIG_SYMLINK_OR_OBJECT_INVALID",
                    detail: "integration config must be a bounded non-symlink regular file"
                        .to_string(),
                };
            }
            let Ok(bytes) = fs::read(&cfg_path) else {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_label),
                    reason_code: "CONFIG_READ_ERROR",
                    detail: "failed reading integration config".to_string(),
                };
            };
            let sha = sha256_hex(&bytes);
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_label),
                    reason_code: "CONFIG_NON_UTF8",
                    detail: "integration config contains invalid UTF-8".to_string(),
                };
            };
            if adapter_id != "codex" && JsonValue::parse(text).is_err() {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_label),
                    reason_code: "CONFIG_MALFORMED_JSON",
                    detail: "integration config contains malformed JSON".to_string(),
                };
            }
            let bin_matches = match verified_bin_canon {
                Some(ref bin) => {
                    adapter_id == "codex" || text.contains(&bin.to_string_lossy().into_owned())
                }
                None => false,
            };
            if !bin_matches {
                return ConfigState::Invalid {
                    adapter_id: adapter_id.to_string(),
                    config_rel_path: Some(rel_label),
                    reason_code: "CONFIG_BINARY_MISMATCH",
                    detail: "integration config does not reference the verified agent-guard binary"
                        .to_string(),
                };
            }
            ConfigState::Valid {
                adapter_id: adapter_id.to_string(),
                config_rel_path: rel_label,
                config_sha256: sha,
                pinned_binary_matches: true,
                protocol_compatible: true,
            }
        }
        _ => ConfigState::Invalid {
            adapter_id: adapter_id.to_string(),
            config_rel_path: None,
            reason_code: "UNSUPPORTED_ADAPTER",
            detail: format!("unsupported adapter identifier '{adapter_id}'"),
        },
    }
}

/// Evaluates Property 5 (`KernelEnforcement`) separating Landlock, seccomp-bpf, Seatbelt, and netns.
pub fn evaluate_kernel_state(snapshot: &ProbeSnapshot) -> KernelEnforcement {
    let os = std::env::consts::OS;
    match os {
        "linux" => {
            let landlock = match snapshot.kernel_fs_mode {
                KernelSandboxMode::LinuxLandlockEnforced => LandlockState::Enforced,
                KernelSandboxMode::LinuxLandlockPartiallyEnforced => {
                    LandlockState::PartiallyEnforced
                }
                _ => LandlockState::Unavailable,
            };
            let seccomp = match snapshot.seccomp_net {
                Some(true) => SeccompState::Verified,
                Some(false) => SeccompState::Unavailable,
                None => SeccompState::NotApplicable,
            };
            let seatbelt = SeatbeltState::NotApplicable;
            match (landlock, seccomp) {
                (LandlockState::Enforced, SeccompState::Verified) => KernelEnforcement::Full {
                    landlock,
                    seccomp,
                    seatbelt,
                    netns_unshare: snapshot.netns_unshare,
                },
                (LandlockState::Enforced, _) => KernelEnforcement::Partial {
                    landlock,
                    seccomp,
                    seatbelt,
                    netns_unshare: snapshot.netns_unshare,
                    reason_code: "SECCOMP_UNAVAILABLE_LANDLOCK_ACTIVE",
                    detail: "Linux Landlock VFS boundary is active, but seccomp-bpf socket filter is unavailable".to_string(),
                },
                (LandlockState::PartiallyEnforced, _) => KernelEnforcement::Partial {
                    landlock,
                    seccomp,
                    seatbelt,
                    netns_unshare: snapshot.netns_unshare,
                    reason_code: "LANDLOCK_PARTIALLY_ENFORCED",
                    detail: "Linux kernel supports partial Landlock ABI only".to_string(),
                },
                (LandlockState::Unavailable, SeccompState::Verified) => {
                    KernelEnforcement::Partial {
                        landlock,
                        seccomp,
                        seatbelt,
                        netns_unshare: snapshot.netns_unshare,
                        reason_code: "LANDLOCK_UNAVAILABLE_SECCOMP_VERIFIED",
                        detail: "Linux Landlock VFS boundary is unavailable; seccomp-bpf AF_UNIX/AF_NETLINK socket filter is verified for exec-sandbox children".to_string(),
                    }
                }
                _ => KernelEnforcement::Unavailable {
                    landlock,
                    seccomp,
                    seatbelt,
                    netns_unshare: snapshot.netns_unshare,
                    reason_code: "KERNEL_SANDBOX_UNAVAILABLE",
                    detail: "Neither Linux Landlock VFS sandboxing nor seccomp-bpf socket filtering is available".to_string(),
                },
            }
        }
        "macos" => {
            let seatbelt = if snapshot.kernel_fs_mode == KernelSandboxMode::MacosSeatbeltEnforced {
                SeatbeltState::Enforced
            } else {
                SeatbeltState::Unavailable
            };
            if seatbelt == SeatbeltState::Enforced {
                KernelEnforcement::Full {
                    landlock: LandlockState::NotApplicable,
                    seccomp: SeccompState::NotApplicable,
                    seatbelt,
                    netns_unshare: false,
                }
            } else {
                KernelEnforcement::Unavailable {
                    landlock: LandlockState::NotApplicable,
                    seccomp: SeccompState::NotApplicable,
                    seatbelt,
                    netns_unshare: false,
                    reason_code: "KERNEL_SANDBOX_UNAVAILABLE",
                    detail: "macOS Seatbelt (/usr/bin/sandbox-exec) is unavailable".to_string(),
                }
            }
        }
        _ => KernelEnforcement::Unavailable {
            landlock: LandlockState::NotApplicable,
            seccomp: SeccompState::NotApplicable,
            seatbelt: SeatbeltState::NotApplicable,
            netns_unshare: false,
            reason_code: "KERNEL_SANDBOX_UNAVAILABLE",
            detail: format!("OS '{os}' has no supported kernel sandbox backend"),
        },
    }
}

enum ReceiptCheck {
    Absent,
    Valid(VerificationReceipt),
    Rejected { code: &'static str, detail: String },
}

fn inspect_verification_receipt(
    workspace: &Path,
    adapter_id: &str,
    expected_mode: &str,
    expected_ws_sha: &str,
    expected_cfg_sha: Option<&str>,
    expected_bin_ver: Option<&str>,
    expected_bin_sha: Option<&str>,
) -> ReceiptCheck {
    let dir = state_base_dir().join("enforcement");
    let slot = slot_prefix_for(workspace, adapter_id);
    let receipt_path = dir.join(format!("receipt_{slot}.json"));
    let meta = match fs::symlink_metadata(&receipt_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ReceiptCheck::Absent,
        Err(_) => {
            return ReceiptCheck::Rejected {
                code: "MALFORMED_CAPABILITY_RECORD",
                detail: "cannot stat capability verification receipt".to_string(),
            };
        }
    };
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.len() > MAX_CAPABILITY_RECORD_BYTES
    {
        return ReceiptCheck::Rejected {
            code: "MALFORMED_CAPABILITY_RECORD",
            detail: "capability verification receipt is not a bounded regular file".to_string(),
        };
    }
    let key = match load_existing_verify_key(&dir) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return ReceiptCheck::Rejected {
                code: "FORGED_EVIDENCE_REJECTED",
                detail:
                    "capability verification receipt exists without a trusted host verification key"
                        .to_string(),
            };
        }
        Err(code) => {
            return ReceiptCheck::Rejected {
                code,
                detail: "host verification key failed integrity validation".to_string(),
            };
        }
    };

    let Ok(raw) = fs::read_to_string(&receipt_path) else {
        return ReceiptCheck::Rejected {
            code: "MALFORMED_CAPABILITY_RECORD",
            detail: "capability verification receipt is unreadable or non-UTF8".to_string(),
        };
    };
    let Ok(parsed) = JsonValue::parse(&raw) else {
        return ReceiptCheck::Rejected {
            code: "MALFORMED_CAPABILITY_RECORD",
            detail: "capability verification receipt contains malformed JSON".to_string(),
        };
    };
    let schema = parsed.get("schema").and_then(JsonValue::as_str);
    let challenge_id = parsed.get("challenge_id").and_then(JsonValue::as_str);
    let verified_at = parsed.get("verified_at_unix").and_then(JsonValue::as_u64);
    let rec_adapter = parsed.get("adapter_id").and_then(JsonValue::as_str);
    let rec_mode = parsed.get("execution_mode").and_then(JsonValue::as_str);
    let rec_ws_sha = parsed.get("workspace_sha256").and_then(JsonValue::as_str);
    let rec_cfg_sha = parsed.get("config_sha256").and_then(JsonValue::as_str);
    let rec_bin_ver = parsed.get("binary_version").and_then(JsonValue::as_str);
    let rec_bin_sha = parsed.get("binary_sha256").and_then(JsonValue::as_str);
    let rec_mac_hex = parsed.get("mac").and_then(JsonValue::as_str);

    let (
        Some("dotagent.enforcement_receipt.v1"),
        Some(cid),
        Some(ts),
        Some(aid),
        Some(em),
        Some(wsha),
        Some(csha),
        Some(bver),
        Some(bsha),
        Some(mhex),
    ) = (
        schema,
        challenge_id,
        verified_at,
        rec_adapter,
        rec_mode,
        rec_ws_sha,
        rec_cfg_sha,
        rec_bin_ver,
        rec_bin_sha,
        rec_mac_hex,
    )
    else {
        return ReceiptCheck::Rejected {
            code: "MALFORMED_CAPABILITY_RECORD",
            detail: "capability verification receipt is missing required bound fields".to_string(),
        };
    };

    let Ok(provided_mac) = hex_decode_32(mhex) else {
        return ReceiptCheck::Rejected {
            code: "MALFORMED_CAPABILITY_RECORD",
            detail: "capability verification receipt contains invalid hex MAC".to_string(),
        };
    };
    let ts_str = ts.to_string();
    let expected_mac = compute_hmac_tag(
        &key,
        b"dotagent.enforcement_receipt.v1",
        &[cid, &ts_str, aid, em, wsha, csha, bver, bsha],
    );
    if !constant_time_eq_bytes(&provided_mac, &expected_mac) {
        return ReceiptCheck::Rejected {
            code: "FORGED_EVIDENCE_REJECTED",
            detail: "capability verification receipt failed HMAC authenticity verification"
                .to_string(),
        };
    }

    if aid != adapter_id {
        return ReceiptCheck::Rejected {
            code: "ADAPTER_EVIDENCE_MISMATCH",
            detail: format!("receipt bound to adapter '{aid}', expected '{adapter_id}'"),
        };
    }
    if wsha != expected_ws_sha {
        return ReceiptCheck::Rejected {
            code: "STALE_WORKSPACE_EVIDENCE",
            detail: "verification receipt is bound to a different workspace digest".to_string(),
        };
    }
    if let (Some(exp_ver), Some(exp_bsha)) = (expected_bin_ver, expected_bin_sha) {
        if bver != exp_ver || bsha != exp_bsha {
            return ReceiptCheck::Rejected {
                code: "STALE_BINARY_EVIDENCE",
                detail: format!(
                    "verification receipt bound to binary v{bver} ({}), current binary is v{exp_ver} ({})",
                    &bsha[..bsha.len().min(12)],
                    &exp_bsha[..exp_bsha.len().min(12)]
                ),
            };
        }
    } else {
        return ReceiptCheck::Rejected {
            code: "BINARY_NOT_VERIFIED",
            detail: "cannot validate verification receipt because installed binary is unverified"
                .to_string(),
        };
    }
    if let Some(exp_csha) = expected_cfg_sha {
        if csha != exp_csha {
            return ReceiptCheck::Rejected {
                code: "STALE_CONFIG_EVIDENCE",
                detail: "verification receipt predates current hook configuration digest"
                    .to_string(),
            };
        }
    } else {
        return ReceiptCheck::Rejected {
            code: "INTEGRATION_UNCONFIGURED",
            detail: "verification receipt invalid because integration configuration is missing or invalid".to_string(),
        };
    }
    if em != expected_mode {
        return ReceiptCheck::Rejected {
            code: "EXECUTION_MODE_MISMATCH",
            detail: format!(
                "verification receipt bound to execution mode '{em}', current mode is '{expected_mode}'"
            ),
        };
    }

    ReceiptCheck::Valid(VerificationReceipt {
        challenge_id: cid.to_string(),
        verified_at_unix: ts,
        adapter_id: aid.to_string(),
        execution_mode: em.to_string(),
        workspace_sha256: wsha.to_string(),
        config_sha256: csha.to_string(),
        binary_version: bver.to_string(),
        binary_sha256: bsha.to_string(),
    })
}

struct DiagnosticInvocationSummary {
    count: u64,
    last_ts_unix: Option<u64>,
    last_event: Option<String>,
    source: EvidenceSource,
    malformed_error: Option<String>,
}

fn inspect_diagnostic_invocations(
    workspace: &Path,
    adapter_id: &str,
    trace_log: Option<&Path>,
    session_id: Option<&str>,
) -> DiagnosticInvocationSummary {
    // 1. Check pending uncompleted HookDenialWitness first
    let enf_dir = state_base_dir().join("enforcement");
    let slot = slot_prefix_for(workspace, adapter_id);
    let witness_path = enf_dir.join(format!("witness_{slot}.json"));
    if let Ok(meta) = fs::symlink_metadata(&witness_path) {
        if meta.file_type().is_symlink()
            || !meta.file_type().is_file()
            || meta.len() > MAX_CAPABILITY_RECORD_BYTES
        {
            return DiagnosticInvocationSummary {
                count: 0,
                last_ts_unix: None,
                last_event: None,
                source: EvidenceSource::None,
                malformed_error: Some("denial witness file is malformed or oversized".to_string()),
            };
        }
        if let Ok(raw) = fs::read_to_string(&witness_path) {
            match JsonValue::parse(&raw) {
                Ok(parsed) => {
                    let ts = parsed.get("witnessed_at_unix").and_then(JsonValue::as_u64);
                    let ev = parsed
                        .get("event")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string);
                    if ts.is_some() && ev.is_some() {
                        return DiagnosticInvocationSummary {
                            count: 1,
                            last_ts_unix: ts,
                            last_event: ev,
                            source: EvidenceSource::HookDenialWitness,
                            malformed_error: None,
                        };
                    }
                    return DiagnosticInvocationSummary {
                        count: 0,
                        last_ts_unix: None,
                        last_event: None,
                        source: EvidenceSource::None,
                        malformed_error: Some(
                            "denial witness JSON missing required fields".to_string(),
                        ),
                    };
                }
                Err(_) => {
                    return DiagnosticInvocationSummary {
                        count: 0,
                        last_ts_unix: None,
                        last_event: None,
                        source: EvidenceSource::None,
                        malformed_error: Some("denial witness contains malformed JSON".to_string()),
                    };
                }
            }
        }
    }

    // 2. Check optional opt-in `--trace-log` (`dotagent.antigravity.invocation.v1`) -- strictly self-reported diagnostic!
    if let Some(tp) = trace_log
        && tp.is_absolute()
        && !tp.components().any(|c| matches!(c, Component::ParentDir))
        && let Ok(meta) = fs::symlink_metadata(tp)
    {
        if meta.file_type().is_symlink()
            || !meta.file_type().is_file()
            || meta.len() > MAX_TRACE_INSPECT_BYTES
        {
            return DiagnosticInvocationSummary {
                count: 0,
                last_ts_unix: None,
                last_event: None,
                source: EvidenceSource::None,
                malformed_error: Some(
                    "trace log is a symlink, non-file, or exceeds 256 KiB".to_string(),
                ),
            };
        }
        if let Ok(raw) = fs::read_to_string(tp) {
            let mut count = 0u64;
            let mut last_ts = None;
            let mut last_ev = None;
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let Ok(val) = JsonValue::parse(line) else {
                    return DiagnosticInvocationSummary {
                        count: 0,
                        last_ts_unix: None,
                        last_event: None,
                        source: EvidenceSource::None,
                        malformed_error: Some(
                            "trace log contains malformed JSONL entry".to_string(),
                        ),
                    };
                };
                if val.get("schema").and_then(JsonValue::as_str)
                    != Some("dotagent.antigravity.invocation.v1")
                {
                    return DiagnosticInvocationSummary {
                        count: 0,
                        last_ts_unix: None,
                        last_event: None,
                        source: EvidenceSource::None,
                        malformed_error: Some(
                            "trace log entry missing expected schema".to_string(),
                        ),
                    };
                }
                let Some(ts) = val.get("ts_unix").and_then(JsonValue::as_u64) else {
                    return DiagnosticInvocationSummary {
                        count: 0,
                        last_ts_unix: None,
                        last_event: None,
                        source: EvidenceSource::None,
                        malformed_error: Some("trace log entry missing ts_unix".to_string()),
                    };
                };
                let Some(ev) = val.get("event").and_then(JsonValue::as_str) else {
                    return DiagnosticInvocationSummary {
                        count: 0,
                        last_ts_unix: None,
                        last_event: None,
                        source: EvidenceSource::None,
                        malformed_error: Some("trace log entry missing event".to_string()),
                    };
                };
                count = count.saturating_add(1);
                last_ts = Some(ts);
                last_ev = Some(ev.to_string());
            }
            if count > 0 {
                return DiagnosticInvocationSummary {
                    count,
                    last_ts_unix: last_ts,
                    last_event: last_ev,
                    source: EvidenceSource::LocalTraceLog,
                    malformed_error: None,
                };
            }
        }
    }

    // 3. Check local SessionLedger for optional `--session <id>` -- strictly self-reported diagnostic!
    if let Some(sid) = session_id.filter(|s| !s.trim().is_empty()) {
        let repo_root = resolve_repo_root(workspace);
        let lpath = session_ledger_path(&repo_root, sid);
        if let Ok(meta) = fs::symlink_metadata(&lpath)
            && meta.file_type().is_file()
            && !meta.file_type().is_symlink()
        {
            let ledger = SessionLedger::load_or_create(&repo_root, sid);
            if ledger.tool_calls > 0 {
                return DiagnosticInvocationSummary {
                    count: ledger.tool_calls as u64,
                    last_ts_unix: None,
                    last_event: Some("PreToolUse".to_string()),
                    source: EvidenceSource::LocalSessionLedger,
                    malformed_error: None,
                };
            }
        }
    }

    DiagnosticInvocationSummary {
        count: 0,
        last_ts_unix: None,
        last_event: None,
        source: EvidenceSource::None,
        malformed_error: None,
    }
}

/// Evaluates all five enforcement states independently without collapsing or upward inference.
pub fn evaluate_enforcement_report(
    workspace: &Path,
    bin_dir: &Path,
    adapter_id: &str,
    trace_log: Option<&Path>,
    session_id: Option<&str>,
    snapshot: &ProbeSnapshot,
) -> EnforcementReport {
    let version_str = snapshot.effective_version();
    let installed = evaluate_install_state(bin_dir, version_str);
    let configured = evaluate_config_state(workspace, adapter_id, &installed);
    let kernel_enforced = evaluate_kernel_state(snapshot);

    let (_, ws_sha) = canonical_workspace_digest(workspace);
    let cfg_sha = match &configured {
        ConfigState::Valid { config_sha256, .. } => Some(config_sha256.as_str()),
        _ => None,
    };
    let (bin_ver, bin_sha) = match &installed {
        InstallState::Verified {
            version,
            binary_sha256,
            ..
        } => (Some(version.as_str()), Some(binary_sha256.as_str())),
        _ => (None, None),
    };
    let protocol_compatible = matches!(
        &configured,
        ConfigState::Valid {
            protocol_compatible: true,
            ..
        }
    );

    let receipt_check = inspect_verification_receipt(
        workspace,
        adapter_id,
        snapshot.execution_mode.as_str(),
        &ws_sha,
        cfg_sha,
        bin_ver,
        bin_sha,
    );
    let diag = inspect_diagnostic_invocations(workspace, adapter_id, trace_log, session_id);

    let mut limitations = Vec::new();

    match &installed {
        InstallState::Verified { .. } => {}
        InstallState::Missing {
            expected_path,
            reason_code,
        } => limitations.push(CapabilityLimitation {
            capability: "installed",
            code: reason_code,
            detail: format!("verified agent-guard binary missing at '{expected_path}'"),
        }),
        InstallState::IntegrityFailed {
            reason_code,
            detail,
            ..
        } => limitations.push(CapabilityLimitation {
            capability: "installed",
            code: reason_code,
            detail: detail.clone(),
        }),
    }

    match &configured {
        ConfigState::Valid { .. } => {}
        ConfigState::Unconfigured { reason_code, .. } => limitations.push(CapabilityLimitation {
            capability: "configured",
            code: reason_code,
            detail: format!("no valid '{adapter_id}' hook configuration deployed in workspace"),
        }),
        ConfigState::Invalid {
            reason_code,
            detail,
            ..
        } => limitations.push(CapabilityLimitation {
            capability: "configured",
            code: reason_code,
            detail: detail.clone(),
        }),
    }

    let (invoked, host_enforced) = match receipt_check {
        ReceiptCheck::Valid(rec) => (
            InvocationState::Verified {
                last_observed_ts_unix: rec.verified_at_unix,
                last_event: "PreToolUse".to_string(),
                evidence_source: EvidenceSource::ObserverVerificationReceipt,
                trust_level: TrustLevel::ObserverVerified,
            },
            HostEnforcement::Verified {
                verified_at_unix: rec.verified_at_unix,
                challenge_id: rec.challenge_id,
                evidence_source: EvidenceSource::ObserverVerificationReceipt,
                trust_level: TrustLevel::ObserverVerified,
            },
        ),
        ReceiptCheck::Rejected { code, detail } => {
            limitations.push(CapabilityLimitation {
                capability: "host_enforced",
                code,
                detail: detail.clone(),
            });
            let inv = if diag.count > 0 {
                InvocationState::DiagnosticOnly {
                    last_observed_ts_unix: diag.last_ts_unix,
                    last_event: diag.last_event,
                    observed_count: diag.count,
                    evidence_source: diag.source,
                    trust_level: TrustLevel::SelfReportedDiagnostic,
                    reason_code: "SELF_REPORTED_INVOCATION_UNATTESTED",
                }
            } else {
                InvocationState::NoneObserved { reason_code: code }
            };
            (
                inv,
                HostEnforcement::Unverified {
                    reason_code: code,
                    detail,
                },
            )
        }
        ReceiptCheck::Absent => {
            if let Some(malformed_msg) = diag.malformed_error {
                limitations.push(CapabilityLimitation {
                    capability: "invoked",
                    code: "MALFORMED_CAPABILITY_RECORD",
                    detail: malformed_msg.clone(),
                });
                (
                    InvocationState::NoneObserved {
                        reason_code: "MALFORMED_CAPABILITY_RECORD",
                    },
                    HostEnforcement::Unverified {
                        reason_code: "MALFORMED_CAPABILITY_RECORD",
                        detail: malformed_msg,
                    },
                )
            } else {
                let inv = if diag.count > 0 {
                    let inv_code = if diag.source == EvidenceSource::HookDenialWitness {
                        "INVOCATION_WITHOUT_ENFORCEMENT_PROOF"
                    } else {
                        "SELF_REPORTED_INVOCATION_UNATTESTED"
                    };
                    limitations.push(CapabilityLimitation {
                        capability: "invoked",
                        code: inv_code,
                        detail: "diagnostic invocation records cannot independently prove authentic host dispatch or host-enforced denial".to_string(),
                    });
                    InvocationState::DiagnosticOnly {
                        last_observed_ts_unix: diag.last_ts_unix,
                        last_event: diag.last_event,
                        observed_count: diag.count,
                        evidence_source: diag.source,
                        trust_level: TrustLevel::SelfReportedDiagnostic,
                        reason_code: inv_code,
                    }
                } else {
                    limitations.push(CapabilityLimitation {
                        capability: "invoked",
                        code: "NO_INVOCATIONS_OBSERVED",
                        detail:
                            "no adapter invocations observed for the inspected workspace/session"
                                .to_string(),
                    });
                    InvocationState::NoneObserved {
                        reason_code: "NO_INVOCATIONS_OBSERVED",
                    }
                };

                let host_state = match &snapshot.execution_mode {
                    ExecutionMode::AntigravityRemoteAgentsVm => {
                        let detail = "no verified automatic hook mediation in the tested Antigravity Remote Agents VM configuration; host enforcement is not verified for this execution mode".to_string();
                        limitations.push(CapabilityLimitation {
                            capability: "host_enforced",
                            code: "HOST_EXECUTION_MODE_UNVERIFIED",
                            detail: detail.clone(),
                        });
                        HostEnforcement::NotVerifiedForExecutionMode {
                            execution_mode: snapshot.execution_mode.as_str().to_string(),
                            reason_code: "HOST_EXECUTION_MODE_UNVERIFIED",
                            detail,
                        }
                    }
                    ExecutionMode::UnsupportedHost(mode_name) => {
                        let detail = format!(
                            "execution mode '{mode_name}' has no verified host hook enforcement support"
                        );
                        limitations.push(CapabilityLimitation {
                            capability: "host_enforced",
                            code: "UNSUPPORTED_EXECUTION_MODE",
                            detail: detail.clone(),
                        });
                        HostEnforcement::NotVerifiedForExecutionMode {
                            execution_mode: mode_name.clone(),
                            reason_code: "UNSUPPORTED_EXECUTION_MODE",
                            detail,
                        }
                    }
                    ExecutionMode::LocalHost => {
                        let (code, detail) = if !matches!(installed, InstallState::Verified { .. })
                        {
                            (
                                "BINARY_NOT_VERIFIED",
                                "host enforcement cannot be verified without a verified agent-guard executable".to_string(),
                            )
                        } else if !matches!(configured, ConfigState::Valid { .. }) {
                            (
                                "INTEGRATION_UNCONFIGURED",
                                "host enforcement cannot be verified until valid hook configuration is installed".to_string(),
                            )
                        } else if diag.count > 0 {
                            (
                                "INVOCATION_WITHOUT_ENFORCEMENT_PROOF",
                                "invocations were recorded diagnostically, but no independent observer has verified that the host honors authoritative denials and prevents side effects".to_string(),
                            )
                        } else {
                            (
                                "HOST_ENFORCEMENT_UNVERIFIED",
                                "configuration is valid, but live host-enforced denial has not been verified for this workspace, config, and binary digest".to_string(),
                            )
                        };
                        limitations.push(CapabilityLimitation {
                            capability: "host_enforced",
                            code,
                            detail: detail.clone(),
                        });
                        HostEnforcement::Unverified {
                            reason_code: code,
                            detail,
                        }
                    }
                };
                (inv, host_state)
            }
        }
    };

    match &kernel_enforced {
        KernelEnforcement::Full { .. } => {}
        KernelEnforcement::Partial {
            reason_code,
            detail,
            ..
        } => limitations.push(CapabilityLimitation {
            capability: "kernel_enforced",
            code: reason_code,
            detail: detail.clone(),
        }),
        KernelEnforcement::Unavailable {
            reason_code,
            detail,
            ..
        } => limitations.push(CapabilityLimitation {
            capability: "kernel_enforced",
            code: reason_code,
            detail: detail.clone(),
        }),
    }

    let mandatory_protection_verified = matches!(installed, InstallState::Verified { .. })
        && matches!(configured, ConfigState::Valid { .. })
        && matches!(host_enforced, HostEnforcement::Verified { .. });

    EnforcementReport {
        runtime_mode: snapshot.execution_mode.as_str().to_string(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        adapter_id: adapter_id.to_string(),
        adapter_protocol: adapter_protocol_name(adapter_id),
        protocol_compatible,
        installed,
        configured,
        invoked,
        host_enforced,
        kernel_enforced,
        mandatory_protection_verified,
        limitations,
    }
}

/// Builds the canonical length-framed message signed by an independent Ed25519 observer key
/// to attest whether the host prevented execution of the controlled canary request.
pub fn build_observer_verdict_message(
    challenge_id: &str,
    adapter_id: &str,
    workspace_sha256: &str,
    canary_rel_path: &str,
    host_prevented_execution: bool,
) -> Vec<u8> {
    let prevented_tag = if host_prevented_execution { "1" } else { "0" };
    let fields = [
        challenge_id,
        adapter_id,
        workspace_sha256,
        canary_rel_path,
        prevented_tag,
    ];
    let mut out = Vec::from(&b"dotagent.observer_verdict.v1\0"[..]);
    for f in fields {
        let len = u32::try_from(f.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f.as_bytes());
    }
    out
}

/// Signs an authenticated observer verdict using a 32-byte Ed25519 signing seed, returning a
/// 128-hex-character Ed25519 signature suitable for `--observer-sig`.
pub fn sign_observer_verdict(
    signing_key_bytes: &[u8; 32],
    challenge_id: &str,
    adapter_id: &str,
    workspace: &Path,
    canary_rel_path: &str,
    host_prevented_execution: bool,
) -> String {
    let (_, ws_sha) = canonical_workspace_digest(workspace);
    let msg = build_observer_verdict_message(
        challenge_id,
        adapter_id,
        &ws_sha,
        canary_rel_path,
        host_prevented_execution,
    );
    let sk = SigningKey::from_bytes(signing_key_bytes);
    let sig = sk.sign(&msg);
    hex_encode(&sig.to_bytes())
}

/// Derives the 64-hex-character Ed25519 verifying key from a 32-byte observer signing seed.
pub fn derive_observer_pubkey_hex(signing_key_bytes: &[u8; 32]) -> String {
    let sk = SigningKey::from_bytes(signing_key_bytes);
    hex_encode(sk.verifying_key().as_bytes())
}

fn hex_decode_64(hex: &str) -> Result<[u8; 64], String> {
    if hex.len() != 128 {
        return Err("expected 128 hex characters".to_string());
    }
    let hi = hex_decode_32(&hex[..64])?;
    let lo = hex_decode_32(&hex[64..])?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&hi);
    out[32..].copy_from_slice(&lo);
    Ok(out)
}

/// Step A of Phase 4: Issues a bounded challenge bound to exact `(mode, workspace, config, binary)`
/// digests and a pinned Ed25519 observer public key (`observer_pubkey_hex`).
pub fn begin_verification(
    workspace: &Path,
    bin_dir: &Path,
    adapter_id: &str,
    snapshot: &ProbeSnapshot,
    external_observer_available: bool,
    observer_pubkey_hex: &str,
) -> Result<VerificationChallenge, ContractError> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err(ContractError::new(
            "SANDBOX_FORBIDDEN",
            "verify-enforcement cannot run inside an agent worker sandbox",
        ));
    }

    if !snapshot
        .execution_mode
        .supports_local_observer_verification()
        && !external_observer_available
    {
        return Err(ContractError::new(
            "VERIFICATION_UNAVAILABLE",
            format!(
                "execution environment '{}' cannot provide an independent host-enforcement observer inside this runtime",
                snapshot.execution_mode.as_str()
            ),
        ));
    }

    let trimmed_pk = observer_pubkey_hex.trim();
    if trimmed_pk.is_empty() {
        return Err(ContractError::new(
            "OBSERVER_KEY_REQUIRED",
            "begin requires --observer-pubkey <64-hex-ed25519-pubkey> to bind independent observer attestation",
        ));
    }
    let pk_bytes = hex_decode_32(trimmed_pk).map_err(|_| {
        ContractError::new(
            "INVALID_OBSERVER_KEY",
            "observer public key must be 64 hexadecimal characters (32-byte Ed25519 verifying key)",
        )
    })?;
    let _ = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
        ContractError::new(
            "INVALID_OBSERVER_KEY",
            "observer public key is not a valid Ed25519 curve point",
        )
    })?;
    let observer_pubkey_norm = trimmed_pk.to_ascii_lowercase();

    let installed = evaluate_install_state(bin_dir, snapshot.effective_version());
    let (bin_ver, bin_sha) = match installed {
        InstallState::Verified {
            version,
            binary_sha256,
            ..
        } => (version, binary_sha256),
        InstallState::Missing { reason_code, .. } => {
            return Err(ContractError::new(
                reason_code,
                "cannot begin enforcement verification without a verified agent-guard binary",
            ));
        }
        InstallState::IntegrityFailed {
            reason_code,
            detail,
            ..
        } => return Err(ContractError::new(reason_code, detail)),
    };

    let configured = evaluate_config_state(
        workspace,
        adapter_id,
        &InstallState::Verified {
            binary_path: bin_dir.join("agent-guard").display().to_string(),
            version: bin_ver.clone(),
            binary_sha256: bin_sha.clone(),
        },
    );
    let cfg_sha = match configured {
        ConfigState::Valid { config_sha256, .. } => config_sha256,
        ConfigState::Unconfigured { reason_code, .. } => {
            return Err(ContractError::new(
                reason_code,
                "cannot begin enforcement verification before hook configuration is installed",
            ));
        }
        ConfigState::Invalid {
            reason_code,
            detail,
            ..
        } => return Err(ContractError::new(reason_code, detail)),
    };

    let dir = enforcement_state_dir()?;
    let key = load_or_create_verify_key(&dir)?;

    let mut nonce = [0u8; 16];
    let mut urandom = fs::File::open("/dev/urandom")
        .map_err(|e| ContractError::new("ENTROPY_IO_ERROR", format!("open /dev/urandom: {e}")))?;
    urandom
        .read_exact(&mut nonce)
        .map_err(|e| ContractError::new("ENTROPY_IO_ERROR", format!("read /dev/urandom: {e}")))?;
    let nonce_hex = hex_encode(&nonce);
    let challenge_id = format!("ch_{nonce_hex}");
    let canary_rel_path = format!(".agents/dotagent-verify-canary-{}.txt", &nonce_hex[..16]);
    let canary_abs = workspace.join(&canary_rel_path);
    if fs::symlink_metadata(&canary_abs).is_ok() {
        return Err(ContractError::new(
            "CANARY_ALREADY_EXISTS",
            "controlled verification canary path already exists prior to test",
        ));
    }

    let (_, ws_sha) = canonical_workspace_digest(workspace);
    let issued_at = current_unix_secs();
    let expires_at = issued_at.saturating_add(CHALLENGE_TTL_SECS);
    let issued_s = issued_at.to_string();
    let expires_s = expires_at.to_string();
    let mode_s = snapshot.execution_mode.as_str();

    let mac = compute_hmac_tag(
        &key,
        b"dotagent.enforcement_challenge.v2",
        &[
            &challenge_id,
            &issued_s,
            &expires_s,
            adapter_id,
            mode_s,
            &ws_sha,
            &cfg_sha,
            &bin_ver,
            &bin_sha,
            &canary_rel_path,
            &observer_pubkey_norm,
        ],
    );
    let doc = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.enforcement_challenge.v2".to_string()),
        ),
        (
            "challenge_id".to_string(),
            JsonValue::Str(challenge_id.clone()),
        ),
        ("issued_at_unix".to_string(), JsonValue::Uint(issued_at)),
        ("expires_at_unix".to_string(), JsonValue::Uint(expires_at)),
        (
            "adapter_id".to_string(),
            JsonValue::Str(adapter_id.to_string()),
        ),
        (
            "execution_mode".to_string(),
            JsonValue::Str(mode_s.to_string()),
        ),
        (
            "workspace_sha256".to_string(),
            JsonValue::Str(ws_sha.clone()),
        ),
        ("config_sha256".to_string(), JsonValue::Str(cfg_sha.clone())),
        (
            "binary_version".to_string(),
            JsonValue::Str(bin_ver.clone()),
        ),
        ("binary_sha256".to_string(), JsonValue::Str(bin_sha.clone())),
        (
            "canary_rel_path".to_string(),
            JsonValue::Str(canary_rel_path.clone()),
        ),
        (
            "observer_pubkey".to_string(),
            JsonValue::Str(observer_pubkey_norm),
        ),
        ("mac".to_string(), JsonValue::Str(hex_encode(&mac))),
    ]);

    let slot = slot_prefix_for(workspace, adapter_id);
    let _ = fs::remove_file(dir.join(format!("witness_{slot}.json")));
    let pending_path = dir.join(format!("pending_{slot}.json"));
    let _ = fs::remove_file(&pending_path);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&pending_path).map_err(|e| {
        ContractError::new("STATE_WRITE_ERROR", format!("write pending challenge: {e}"))
    })?;
    f.write_all(doc.to_json_string().as_bytes()).map_err(|e| {
        ContractError::new("STATE_WRITE_ERROR", format!("write pending challenge: {e}"))
    })?;

    Ok(VerificationChallenge {
        challenge_id,
        issued_at_unix: issued_at,
        expires_at_unix: expires_at,
        adapter_id: adapter_id.to_string(),
        execution_mode: mode_s.to_string(),
        workspace_sha256: ws_sha,
        config_sha256: cfg_sha,
        binary_version: bin_ver,
        binary_sha256: bin_sha,
        canary_rel_path,
    })
}

/// Records a hook-side denial witness (Steps 1 & 2 of Phase 4 ONLY) when an authoritative denial
/// matches an active pending challenge's `canary_rel_path`. Never certifies `HostEnforcement::Verified`
/// and ignores all I/O failures so guard decisions are never altered.
pub fn record_denial_witness(
    workspace: &Path,
    adapter_id: &str,
    event_name: &str,
    raw_input: &[u8],
    deny_code: &str,
) {
    let Ok(raw_str) = std::str::from_utf8(raw_input) else {
        return;
    };
    let dir = state_base_dir().join("enforcement");
    let slot = slot_prefix_for(workspace, adapter_id);
    let pending_path = dir.join(format!("pending_{slot}.json"));
    let Ok(meta) = fs::symlink_metadata(&pending_path) else {
        return;
    };
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || meta.len() > MAX_CAPABILITY_RECORD_BYTES
    {
        return;
    }
    let Ok(Some(key)) = load_existing_verify_key(&dir) else {
        return;
    };
    let Ok(pending_raw) = fs::read_to_string(&pending_path) else {
        return;
    };
    let Ok(parsed) = JsonValue::parse(&pending_raw) else {
        return;
    };
    let Some(canary_rel) = parsed.get("canary_rel_path").and_then(JsonValue::as_str) else {
        return;
    };
    if !raw_str.contains(canary_rel) {
        return;
    }
    let Some(cid) = parsed.get("challenge_id").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(issued) = parsed.get("issued_at_unix").and_then(JsonValue::as_u64) else {
        return;
    };
    let Some(expires) = parsed.get("expires_at_unix").and_then(JsonValue::as_u64) else {
        return;
    };
    let Some(aid) = parsed.get("adapter_id").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(mode_s) = parsed.get("execution_mode").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(ws_sha) = parsed.get("workspace_sha256").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(cfg_sha) = parsed.get("config_sha256").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(bin_ver) = parsed.get("binary_version").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(bin_sha) = parsed.get("binary_sha256").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(obs_pk) = parsed.get("observer_pubkey").and_then(JsonValue::as_str) else {
        return;
    };
    let Some(p_mac_hex) = parsed.get("mac").and_then(JsonValue::as_str) else {
        return;
    };
    let Ok(p_mac) = hex_decode_32(p_mac_hex) else {
        return;
    };
    let issued_s = issued.to_string();
    let expires_s = expires.to_string();
    let exp_p_mac = compute_hmac_tag(
        &key,
        b"dotagent.enforcement_challenge.v2",
        &[
            cid, &issued_s, &expires_s, aid, mode_s, ws_sha, cfg_sha, bin_ver, bin_sha, canary_rel,
            obs_pk,
        ],
    );
    if !constant_time_eq_bytes(&p_mac, &exp_p_mac) {
        return;
    }
    let now = current_unix_secs();
    if now > expires {
        return;
    }

    let now_s = now.to_string();
    let w_mac = compute_hmac_tag(
        &key,
        b"dotagent.denial_witness.v1",
        &[
            cid, &now_s, event_name, deny_code, aid, ws_sha, cfg_sha, bin_ver, bin_sha,
        ],
    );
    let witness_doc = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.denial_witness.v1".to_string()),
        ),
        ("challenge_id".to_string(), JsonValue::Str(cid.to_string())),
        ("witnessed_at_unix".to_string(), JsonValue::Uint(now)),
        ("event".to_string(), JsonValue::Str(event_name.to_string())),
        (
            "denied_code".to_string(),
            JsonValue::Str(deny_code.to_string()),
        ),
        ("adapter_id".to_string(), JsonValue::Str(aid.to_string())),
        (
            "workspace_sha256".to_string(),
            JsonValue::Str(ws_sha.to_string()),
        ),
        (
            "config_sha256".to_string(),
            JsonValue::Str(cfg_sha.to_string()),
        ),
        (
            "binary_version".to_string(),
            JsonValue::Str(bin_ver.to_string()),
        ),
        (
            "binary_sha256".to_string(),
            JsonValue::Str(bin_sha.to_string()),
        ),
        ("mac".to_string(), JsonValue::Str(hex_encode(&w_mac))),
    ]);

    let witness_path = dir.join(format!("witness_{slot}.json"));
    let _ = fs::remove_file(&witness_path);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(&witness_path) {
        let _ = f.write_all(witness_doc.to_json_string().as_bytes());
    }
}

/// Step B of Phase 4: Independent observer verifies hook denial witness, Ed25519-signed observer
/// verdict (`observer_sig_hex`), host rejection, absence of prohibited side effect on disk, and
/// zero drift in `(mode, workspace, config, binary)`.
pub fn complete_verification(
    workspace: &Path,
    bin_dir: &Path,
    adapter_id: &str,
    challenge_id: &str,
    host_prevented_execution: bool,
    observer_sig_hex: Option<&str>,
    snapshot: &ProbeSnapshot,
) -> Result<VerificationReceipt, ContractError> {
    if std::env::var("AGENT_GUARD_IN_SANDBOX").as_deref() == Ok("1")
        || std::env::var("AGENT_GUARD_WORKER_LOCK").as_deref() == Ok("1")
    {
        return Err(ContractError::new(
            "SANDBOX_FORBIDDEN",
            "verify-enforcement cannot run inside an agent worker sandbox",
        ));
    }

    let dir = enforcement_state_dir()?;
    let key = match load_existing_verify_key(&dir) {
        Ok(Some(k)) => k,
        Ok(None) => {
            return Err(ContractError::new(
                "CHALLENGE_NOT_FOUND",
                "no active enforcement verification key or challenge present",
            ));
        }
        Err(code) => {
            return Err(ContractError::new(
                code,
                "host verification key failed integrity validation",
            ));
        }
    };

    let slot = slot_prefix_for(workspace, adapter_id);
    let pending_path = dir.join(format!("pending_{slot}.json"));
    let pending_raw = fs::read_to_string(&pending_path).map_err(|_| {
        ContractError::new(
            "CHALLENGE_NOT_FOUND",
            "no pending enforcement verification challenge found for workspace",
        )
    })?;
    let p_json = JsonValue::parse(&pending_raw).map_err(|_| {
        ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "pending challenge contains malformed JSON",
        )
    })?;
    let (
        Some(p_cid),
        Some(issued),
        Some(expires),
        Some(p_aid),
        Some(p_mode),
        Some(p_ws_sha),
        Some(p_cfg_sha),
        Some(p_bin_ver),
        Some(p_bin_sha),
        Some(canary_rel),
        Some(p_obs_pk),
        Some(p_mac_hex),
    ) = (
        p_json.get("challenge_id").and_then(JsonValue::as_str),
        p_json.get("issued_at_unix").and_then(JsonValue::as_u64),
        p_json.get("expires_at_unix").and_then(JsonValue::as_u64),
        p_json.get("adapter_id").and_then(JsonValue::as_str),
        p_json.get("execution_mode").and_then(JsonValue::as_str),
        p_json.get("workspace_sha256").and_then(JsonValue::as_str),
        p_json.get("config_sha256").and_then(JsonValue::as_str),
        p_json.get("binary_version").and_then(JsonValue::as_str),
        p_json.get("binary_sha256").and_then(JsonValue::as_str),
        p_json.get("canary_rel_path").and_then(JsonValue::as_str),
        p_json.get("observer_pubkey").and_then(JsonValue::as_str),
        p_json.get("mac").and_then(JsonValue::as_str),
    )
    else {
        return Err(ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "pending challenge is missing required fields",
        ));
    };

    let p_mac = hex_decode_32(p_mac_hex).map_err(|_| {
        ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "pending challenge has invalid MAC encoding",
        )
    })?;
    let issued_s = issued.to_string();
    let expires_s = expires.to_string();
    let exp_p_mac = compute_hmac_tag(
        &key,
        b"dotagent.enforcement_challenge.v2",
        &[
            p_cid, &issued_s, &expires_s, p_aid, p_mode, p_ws_sha, p_cfg_sha, p_bin_ver, p_bin_sha,
            canary_rel, p_obs_pk,
        ],
    );
    if !constant_time_eq_bytes(&p_mac, &exp_p_mac) {
        return Err(ContractError::new(
            "FORGED_EVIDENCE_REJECTED",
            "pending challenge failed HMAC authenticity check",
        ));
    }
    if p_cid != challenge_id {
        return Err(ContractError::new(
            "CHALLENGE_ID_MISMATCH",
            "supplied --challenge does not match active workspace challenge",
        ));
    }
    let now = current_unix_secs();
    if now > expires {
        return Err(ContractError::new(
            "CHALLENGE_EXPIRED",
            "enforcement verification challenge expired",
        ));
    }

    // Verify independent Ed25519 observer signature attesting `host_prevented_execution` BEFORE
    // trusting the caller-supplied boolean (preventing self-attestation after direct hook replay).
    let Some(sig_hex_raw) = observer_sig_hex.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(ContractError::new(
            "OBSERVER_ATTESTATION_REQUIRED",
            "complete requires --observer-sig <128-hex-ed25519-signature> from the pinned independent observer key",
        ));
    };
    let pk_bytes = hex_decode_32(p_obs_pk).map_err(|_| {
        ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "pinned observer_pubkey in challenge has invalid encoding",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
        ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "pinned observer_pubkey in challenge is invalid",
        )
    })?;
    let sig_bytes = hex_decode_64(sig_hex_raw).map_err(|_| {
        ContractError::new(
            "FORGED_EVIDENCE_REJECTED",
            "observer signature must be 128 hexadecimal characters (64-byte Ed25519 signature)",
        )
    })?;
    let signature = Signature::from_bytes(&sig_bytes);
    let expected_verdict_msg = build_observer_verdict_message(
        challenge_id,
        p_aid,
        p_ws_sha,
        canary_rel,
        host_prevented_execution,
    );
    verifying_key
        .verify_strict(&expected_verdict_msg, &signature)
        .map_err(|_| {
            ContractError::new(
                "FORGED_EVIDENCE_REJECTED",
                "observer verdict Ed25519 signature failed verification against pinned observer public key",
            )
        })?;

    // Check 1 & 2: Authenticated HookDenialWitness must exist for this exact challenge
    let witness_path = dir.join(format!("witness_{slot}.json"));
    let witness_raw = fs::read_to_string(&witness_path).map_err(|_| {
        ContractError::new(
            "HOOK_NOT_INVOKED",
            "controlled request never reached the expected agent-guard hook",
        )
    })?;
    let w_json = JsonValue::parse(&witness_raw).map_err(|_| {
        ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "denial witness contains malformed JSON",
        )
    })?;
    let (
        Some(w_cid),
        Some(w_ts),
        Some(w_ev),
        Some(w_code),
        Some(w_aid),
        Some(w_ws_sha),
        Some(w_cfg_sha),
        Some(w_bin_ver),
        Some(w_bin_sha),
        Some(w_mac_hex),
    ) = (
        w_json.get("challenge_id").and_then(JsonValue::as_str),
        w_json.get("witnessed_at_unix").and_then(JsonValue::as_u64),
        w_json.get("event").and_then(JsonValue::as_str),
        w_json.get("denied_code").and_then(JsonValue::as_str),
        w_json.get("adapter_id").and_then(JsonValue::as_str),
        w_json.get("workspace_sha256").and_then(JsonValue::as_str),
        w_json.get("config_sha256").and_then(JsonValue::as_str),
        w_json.get("binary_version").and_then(JsonValue::as_str),
        w_json.get("binary_sha256").and_then(JsonValue::as_str),
        w_json.get("mac").and_then(JsonValue::as_str),
    )
    else {
        return Err(ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "denial witness missing required fields",
        ));
    };
    let w_mac = hex_decode_32(w_mac_hex).map_err(|_| {
        ContractError::new(
            "MALFORMED_CAPABILITY_RECORD",
            "denial witness has invalid MAC encoding",
        )
    })?;
    let w_ts_s = w_ts.to_string();
    let exp_w_mac = compute_hmac_tag(
        &key,
        b"dotagent.denial_witness.v1",
        &[
            w_cid, &w_ts_s, w_ev, w_code, w_aid, w_ws_sha, w_cfg_sha, w_bin_ver, w_bin_sha,
        ],
    );
    if !constant_time_eq_bytes(&w_mac, &exp_w_mac) || w_cid != challenge_id {
        return Err(ContractError::new(
            "FORGED_EVIDENCE_REJECTED",
            "denial witness failed HMAC authenticity check",
        ));
    }

    // Check 3: Authenticated observer verdict must attest that the host prevented execution
    if !host_prevented_execution {
        return Err(ContractError::new(
            "HOST_DID_NOT_PREVENT_EXECUTION",
            "host did not honor authoritative guard denial (advisory-only or bypassed)",
        ));
    }

    // Check 4: Independent observer checks that the prohibited canary side effect does NOT exist on disk
    let canary_abs = workspace.join(canary_rel);
    if fs::symlink_metadata(&canary_abs).is_ok() {
        return Err(ContractError::new(
            "PROHIBITED_SIDE_EFFECT_OBSERVED",
            "prohibited canary file exists on disk despite hook denial; host enforcement failed",
        ));
    }

    // Check 5: Exact identity binding check (zero drift in mode, workspace, config, binary version, binary digest)
    let cur_install = evaluate_install_state(bin_dir, snapshot.effective_version());
    let (cur_ver, cur_bin_sha) = match &cur_install {
        InstallState::Verified {
            version,
            binary_sha256,
            ..
        } => (version.as_str(), binary_sha256.as_str()),
        _ => {
            return Err(ContractError::new(
                "BINARY_NOT_VERIFIED",
                "installed binary is no longer verified",
            ));
        }
    };
    let cur_cfg = evaluate_config_state(workspace, adapter_id, &cur_install);
    let cur_cfg_sha = match &cur_cfg {
        ConfigState::Valid { config_sha256, .. } => config_sha256.as_str(),
        _ => {
            return Err(ContractError::new(
                "INTEGRATION_UNCONFIGURED",
                "hook configuration is no longer valid",
            ));
        }
    };
    let (_, cur_ws_sha) = canonical_workspace_digest(workspace);
    let cur_mode = snapshot.execution_mode.as_str();
    if cur_ws_sha != p_ws_sha
        || cur_cfg_sha != p_cfg_sha
        || cur_ver != p_bin_ver
        || cur_bin_sha != p_bin_sha
        || cur_mode != p_mode
    {
        return Err(ContractError::new(
            "BINDING_DRIFT_DETECTED",
            "workspace, hook configuration, execution mode, or binary digest changed during verification",
        ));
    }

    let now_s = now.to_string();
    let r_mac = compute_hmac_tag(
        &key,
        b"dotagent.enforcement_receipt.v1",
        &[
            challenge_id,
            &now_s,
            adapter_id,
            cur_mode,
            &cur_ws_sha,
            cur_cfg_sha,
            cur_ver,
            cur_bin_sha,
        ],
    );
    let receipt_doc = JsonValue::Object(vec![
        (
            "schema".to_string(),
            JsonValue::Str("dotagent.enforcement_receipt.v1".to_string()),
        ),
        (
            "challenge_id".to_string(),
            JsonValue::Str(challenge_id.to_string()),
        ),
        ("verified_at_unix".to_string(), JsonValue::Uint(now)),
        (
            "adapter_id".to_string(),
            JsonValue::Str(adapter_id.to_string()),
        ),
        (
            "execution_mode".to_string(),
            JsonValue::Str(cur_mode.to_string()),
        ),
        (
            "workspace_sha256".to_string(),
            JsonValue::Str(cur_ws_sha.clone()),
        ),
        (
            "config_sha256".to_string(),
            JsonValue::Str(cur_cfg_sha.to_string()),
        ),
        (
            "binary_version".to_string(),
            JsonValue::Str(cur_ver.to_string()),
        ),
        (
            "binary_sha256".to_string(),
            JsonValue::Str(cur_bin_sha.to_string()),
        ),
        ("mac".to_string(), JsonValue::Str(hex_encode(&r_mac))),
    ]);

    let receipt_path = dir.join(format!("receipt_{slot}.json"));
    let _ = fs::remove_file(&receipt_path);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut rf = opts
        .open(&receipt_path)
        .map_err(|e| ContractError::new("STATE_WRITE_ERROR", format!("write receipt: {e}")))?;
    rf.write_all(receipt_doc.to_json_string().as_bytes())
        .map_err(|e| ContractError::new("STATE_WRITE_ERROR", format!("write receipt: {e}")))?;

    let _ = fs::remove_file(&pending_path);
    let _ = fs::remove_file(&witness_path);

    Ok(VerificationReceipt {
        challenge_id: challenge_id.to_string(),
        verified_at_unix: now,
        adapter_id: adapter_id.to_string(),
        execution_mode: cur_mode.to_string(),
        workspace_sha256: cur_ws_sha,
        config_sha256: cur_cfg_sha.to_string(),
        binary_version: cur_ver.to_string(),
        binary_sha256: cur_bin_sha.to_string(),
    })
}

fn default_bin_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let cand = PathBuf::from(home).join(".local/bin");
        if cand.is_dir() {
            return cand;
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(p) = exe.parent()
    {
        return p.to_path_buf();
    }
    PathBuf::from(".local/bin")
}

/// CLI entrypoint for `dotagent status [--json] [--adapter <id>] [--execution-mode <mode>] [--bin-dir <dir>] [--trace-log <path>] [--session <id>] [--require-host-enforced] [workspace]`.
pub fn run_status_cli(args: &[String], cwd: &Path) -> ExitCode {
    let mut json_mode = false;
    let mut require_host_enforced = false;
    let mut adapter_id = "antigravity".to_string();
    let mut mode_override: Option<String> = None;
    let mut bin_dir_opt: Option<PathBuf> = None;
    let mut trace_log_opt: Option<PathBuf> = None;
    let mut session_opt: Option<String> = None;
    let mut target_ws_opt: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json_mode = true;
                i += 1;
            }
            "--require-host-enforced" => {
                require_host_enforced = true;
                i += 1;
            }
            "--adapter" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[status] missing value after --adapter");
                    return ExitCode::from(2);
                };
                adapter_id = v.clone();
                i += 2;
            }
            "--execution-mode" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[status] missing value after --execution-mode");
                    return ExitCode::from(2);
                };
                mode_override = Some(v.clone());
                i += 2;
            }
            "--bin-dir" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[status] missing path after --bin-dir");
                    return ExitCode::from(2);
                };
                bin_dir_opt = Some(PathBuf::from(v));
                i += 2;
            }
            "--trace-log" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[status] missing path after --trace-log");
                    return ExitCode::from(2);
                };
                trace_log_opt = Some(PathBuf::from(v));
                i += 2;
            }
            "--session" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[status] missing session id after --session");
                    return ExitCode::from(2);
                };
                session_opt = Some(v.clone());
                i += 2;
            }
            other if !other.starts_with('-') && target_ws_opt.is_none() => {
                target_ws_opt = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[status] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let snapshot = match ProbeSnapshot::probe_live(mode_override.as_deref()) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("[status] {msg}");
            return ExitCode::from(2);
        }
    };
    let target_ws = target_ws_opt.unwrap_or_else(|| resolve_repo_root(cwd));
    let bin_dir = bin_dir_opt.unwrap_or_else(default_bin_dir);
    let report = evaluate_enforcement_report(
        &target_ws,
        &bin_dir,
        &adapter_id,
        trace_log_opt.as_deref(),
        session_opt.as_deref(),
        &snapshot,
    );

    if json_mode {
        println!("{}", report.to_json_value().to_json_string());
    } else {
        print!("{}", report.format_human());
    }

    if require_host_enforced && !report.mandatory_protection_verified {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// CLI entrypoint for `dotagent verify-enforcement <begin|complete> ...`.
pub fn run_verify_enforcement_cli(args: &[String], cwd: &Path) -> ExitCode {
    let Some(sub) = args.first().map(String::as_str) else {
        eprintln!(
            "[verify-enforcement] usage: dotagent verify-enforcement <begin|complete> [--json] [--adapter <id>] [--execution-mode <mode>] [--bin-dir <dir>] [options] [workspace]"
        );
        return ExitCode::from(2);
    };

    let mut json_mode = false;
    let mut adapter_id = "antigravity".to_string();
    let mut mode_override: Option<String> = None;
    let mut bin_dir_opt: Option<PathBuf> = None;
    let mut challenge_id: Option<String> = None;
    let mut host_prevented: Option<bool> = None;
    let mut observer_pubkey: Option<String> = None;
    let mut observer_sig: Option<String> = None;
    let mut external_observer = false;
    let mut target_ws_opt: Option<PathBuf> = None;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json_mode = true;
                i += 1;
            }
            "--external-observer" => {
                external_observer = true;
                i += 1;
            }
            "--adapter" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[verify-enforcement] missing value after --adapter");
                    return ExitCode::from(2);
                };
                adapter_id = v.clone();
                i += 2;
            }
            "--execution-mode" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[verify-enforcement] missing value after --execution-mode");
                    return ExitCode::from(2);
                };
                mode_override = Some(v.clone());
                i += 2;
            }
            "--bin-dir" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[verify-enforcement] missing path after --bin-dir");
                    return ExitCode::from(2);
                };
                bin_dir_opt = Some(PathBuf::from(v));
                i += 2;
            }
            "--challenge" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[verify-enforcement] missing value after --challenge");
                    return ExitCode::from(2);
                };
                challenge_id = Some(v.clone());
                i += 2;
            }
            "--observer-pubkey" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[verify-enforcement] missing hex key after --observer-pubkey");
                    return ExitCode::from(2);
                };
                observer_pubkey = Some(v.clone());
                i += 2;
            }
            "--observer-sig" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("[verify-enforcement] missing hex signature after --observer-sig");
                    return ExitCode::from(2);
                };
                observer_sig = Some(v.clone());
                i += 2;
            }
            "--host-prevented-execution" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!(
                        "[verify-enforcement] missing true|false after --host-prevented-execution"
                    );
                    return ExitCode::from(2);
                };
                match v.as_str() {
                    "true" => host_prevented = Some(true),
                    "false" => host_prevented = Some(false),
                    other => {
                        eprintln!(
                            "[verify-enforcement] invalid boolean '{other}' for --host-prevented-execution"
                        );
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            other if !other.starts_with('-') && target_ws_opt.is_none() => {
                target_ws_opt = Some(PathBuf::from(other));
                i += 1;
            }
            other => {
                eprintln!("[verify-enforcement] unrecognized argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let snapshot = match ProbeSnapshot::probe_live(mode_override.as_deref()) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("[verify-enforcement] {msg}");
            return ExitCode::from(2);
        }
    };
    let target_ws = target_ws_opt.unwrap_or_else(|| resolve_repo_root(cwd));
    let bin_dir = bin_dir_opt.unwrap_or_else(default_bin_dir);

    match sub {
        "begin" => match begin_verification(
            &target_ws,
            &bin_dir,
            &adapter_id,
            &snapshot,
            external_observer,
            observer_pubkey.as_deref().unwrap_or(""),
        ) {
            Ok(ch) => {
                if json_mode {
                    let doc = JsonValue::Object(vec![
                        ("status".to_string(), JsonValue::Str("issued".to_string())),
                        ("challenge_id".to_string(), JsonValue::Str(ch.challenge_id)),
                        (
                            "canary_rel_path".to_string(),
                            JsonValue::Str(ch.canary_rel_path),
                        ),
                        (
                            "expires_at_unix".to_string(),
                            JsonValue::Uint(ch.expires_at_unix),
                        ),
                    ]);
                    println!("{}", doc.to_json_string());
                } else {
                    println!(
                        "[verify-enforcement] challenge='{}' canary='{}' expires_at={}",
                        ch.challenge_id, ch.canary_rel_path, ch.expires_at_unix
                    );
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                if json_mode {
                    let doc = JsonValue::Object(vec![
                        ("status".to_string(), JsonValue::Str("error".to_string())),
                        ("code".to_string(), JsonValue::Str(err.code.to_string())),
                        ("detail".to_string(), JsonValue::Str(err.detail)),
                    ]);
                    println!("{}", doc.to_json_string());
                } else {
                    eprintln!("[verify-enforcement :: {}] {}", err.code, err.detail);
                }
                ExitCode::from(2)
            }
        },
        "complete" => {
            let Some(cid) = challenge_id else {
                eprintln!("[verify-enforcement] complete requires --challenge <id>");
                return ExitCode::from(2);
            };
            let Some(prevented) = host_prevented else {
                eprintln!(
                    "[verify-enforcement] complete requires --host-prevented-execution <true|false>"
                );
                return ExitCode::from(2);
            };
            match complete_verification(
                &target_ws,
                &bin_dir,
                &adapter_id,
                &cid,
                prevented,
                observer_sig.as_deref(),
                &snapshot,
            ) {
                Ok(rec) => {
                    if json_mode {
                        let doc = JsonValue::Object(vec![
                            ("status".to_string(), JsonValue::Str("verified".to_string())),
                            ("challenge_id".to_string(), JsonValue::Str(rec.challenge_id)),
                            (
                                "verified_at_unix".to_string(),
                                JsonValue::Uint(rec.verified_at_unix),
                            ),
                            (
                                "binary_sha256".to_string(),
                                JsonValue::Str(rec.binary_sha256),
                            ),
                            (
                                "config_sha256".to_string(),
                                JsonValue::Str(rec.config_sha256),
                            ),
                        ]);
                        println!("{}", doc.to_json_string());
                    } else {
                        println!(
                            "[verify-enforcement] VERIFIED challenge='{}' ts={}",
                            rec.challenge_id, rec.verified_at_unix
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    if json_mode {
                        let doc = JsonValue::Object(vec![
                            ("status".to_string(), JsonValue::Str("error".to_string())),
                            ("code".to_string(), JsonValue::Str(err.code.to_string())),
                            ("detail".to_string(), JsonValue::Str(err.detail)),
                        ]);
                        println!("{}", doc.to_json_string());
                    } else {
                        eprintln!("[verify-enforcement :: {}] {}", err.code, err.detail);
                    }
                    ExitCode::from(2)
                }
            }
        }
        other => {
            eprintln!(
                "[verify-enforcement] unsupported subcommand '{other}' (expected begin|complete)"
            );
            ExitCode::from(2)
        }
    }
}

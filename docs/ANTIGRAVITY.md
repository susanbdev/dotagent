# Native Antigravity Workspace Integration

Dotagent ships a native Rust protocol adapter (`agent-guard antigravity-hook`) and workspace-scoped operator commands (`dotagent activate --antigravity`, `dotagent deactivate --antigravity`, `dotagent status`, and `dotagent verify-enforcement`) for Google Antigravity workspace hooks (`.agents/hooks.json`).

## Workspace Activation and Deactivation

Activate workspace-scoped hooks without modifying `~/.gitconfig`, shell startup files, or `~/.gemini`:

```sh
dotagent activate --antigravity --workspace /path/to/repo --dotagent-root /path/to/dotagent --bin-dir /path/to/bin
```

Deactivate and restore pre-existing files from verified `.dotagent.bak` backups:

```sh
dotagent deactivate --antigravity --workspace /path/to/repo
```

Activation enforces strict integrity and ownership guarantees:

1. **Mandatory bundle verification (`dist-verify/manifest.sha256`)**: Activation refuses missing, empty, malformed, or incomplete manifests and verifies SHA-256 digests for `dist/antigravity/hooks.json` and every `dist/antigravity/agents/*.md` artifact before touching the workspace.
2. **Explicit ownership provenance (`.agents/.dotagent-manifest.json`)**: Activation records per-file provenance (`pre_existing`, `orig_mode`, `orig_sha256`, `deployed_sha256`, and `managed_group`), including `.dotagent.bak` backups for pre-existing files whose bytes already match generated artifacts.
3. **Reversible, non-destructive deactivation**: Deactivation never deletes files based on `0444` permissions or content markers alone. If `.agents/hooks.json` or a managed file was externally modified to remove or alter the `dotagent-guard` group, deactivation preserves `.dotagent.bak` and `.dotagent-manifest.json` intact and reports a missing/changed managed namespace error. Unrelated sibling hook groups added after activation are preserved when `dotagent-guard` is intact.

An installed `PreToolUse` entry looks like:

```json
{
  "dotagent-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/dotagent/bin/agent-guard antigravity-hook PreToolUse --workspace /srv/project",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

## Protocol Coverage

| Event or operation | Dotagent behavior |
| --- | --- |
| `PreToolUse` | Validates the envelope, conversation identity, and workspace pin, then evaluates supported tool calls through the shared Rust security kernel. Malformed requests and unsupported tools fail closed with JSON `{"decision":"deny","reason":"..."}` and exit `0`. |
| `run_command` | Evaluates command policy and returns an `overwrite` rewriting `CommandLine` through the canonical `agent-guard exec-sandbox` wrapper with required kernel confinement. |
| `view_file` | Enforces path, secret, Unicode, traversal-hop, and slice/token budgets before authorizing native file reads. |
| Native writes | `write_to_file`, `replace_file_content`, and `multi_replace_file_content` enforce immutable control-plane protection (including `.agents/`), secret/Unicode checks, and artifact-directory restrictions. |
| Search and listing | `list_dir`, `find_by_name`, and `grep_search` enforce forbidden-directory blindness and `<= 2` directory walk depth limits. |
| `SessionStart` | Initializes or loads the conversation ledger without clearing a tripped circuit breaker. |
| `PostToolUse` | Records bounded non-sensitive status metadata without assuming host tool-output payloads. |
| `PreInvocation`, `PostInvocation` | Enforces session circuit-breaker halts (`terminationBehavior: "terminate"`) without resetting turn budgets on automatic re-entry. |
| `Stop` | Audits repository control-plane and swarm ledger invariants when `fullyIdle` is true (`{"decision":"block"}` on violation). |

## Five-State Runtime Enforcement Capability Model

Static configuration does not prove live host mediation. Dotagent separates runtime assurance into five independent capability states (`dotagent status --json <workspace>`):

1. **`Installed`**: Verified `agent-guard` binary integrity and permissions on disk.
2. **`Configured`**: Valid `.agents/hooks.json` with pinned `dotagent-guard` handlers.
3. **`Invoked`**: Tamper-evident live hook dispatch evidence (self-reported CLI replays are classified `diagnostic_only`, never live host invocation).
4. **`HostEnforced`**: Remains `unverified` until an observer-bound `dotagent verify-enforcement <begin|complete>` probe proves that an allowed canary executed, a denied canary was mediated by the host, and the prohibited side effect did not occur.
5. **`KernelEnforced`**: Separate OS sandbox verification (`Landlock` + `seccomp-bpf` child probe on Linux, `Seatbelt` on macOS).

> **Remote Agents Runtime Note**: Direct live testing in Antigravity Remote Agents confirmed that the Rust adapter denies prohibited operations when invoked directly, while the tested Remote Agents VM executed tool calls with zero observed workspace hook invocations (`not_enforced` / `unverified`). Never treat `Installed` + `Configured` alone as active host enforcement; require `--require-host-enforced` when mandatory host mediation is needed.

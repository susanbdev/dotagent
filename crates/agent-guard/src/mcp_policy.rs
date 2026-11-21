#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

//! Declarative Per-RPC MCP Capability Manifest (`Pillar 2`).
//!
//! Classifies `mcp__susanbdev__*` and local `agent-guard mcp-gateway` RPC methods into three
//! strict capability classes:
//! - `ReadOnly`: Pure query/inspection calls (`ping`, `search`, `get_*`, `list_*`, `read_*`, ...).
//! - `WorkspaceWrite`: Local workspace file/sandbox mutations (`dotagent_edit_file`, `write_file`, ...).
//! - `ExternalMutation`: Control-plane / PR / infra / webhook / deployment mutations -- **and the
//!   fail-closed default** for any unrecognized `mcp__susanbdev__*` method!

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpRpcClass {
    ReadOnly,
    WorkspaceWrite,
    ExternalMutation,
}

impl McpRpcClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WorkspaceWrite => "workspace_write",
            Self::ExternalMutation => "external_mutation",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct McpManifestRule {
    pub pattern: &'static str,
    pub class: McpRpcClass,
    pub description: &'static str,
}

/// Canonical declarative capability table exported for both runtime enforcement and Policy-IR compilation.
pub const MCP_CAPABILITY_MANIFEST: &[McpManifestRule] = &[
    McpManifestRule {
        pattern: "ping|health|status|version|dotagent_status|dotagent_submit_friction",
        class: McpRpcClass::ReadOnly,
        description: "Liveness, read-only health metadata, and taint-quarantined friction ballot submission",
    },
    McpManifestRule {
        pattern: "get_*|list_*|read_*|search|search_*|query|query_*|inspect_*|describe_*|explain_*|verify_*|diff|diff_*|check_*|audit_*|lookup_*|dotagent_read_file|dotagent_search",
        class: McpRpcClass::ReadOnly,
        description: "Pure read-only lookup, search, and verification RPCs",
    },
    McpManifestRule {
        pattern: "dotagent_edit_file",
        class: McpRpcClass::WorkspaceWrite,
        description: "Local mediated workspace edit tool gated by enable_write_tools and path_policy",
    },
    McpManifestRule {
        pattern: "create_*|update_*|delete_*|remove_*|write_*|edit_*|patch_*|fetch_*|merge_*|close_*|reopen_*|approve_*|comment_*|deploy_*|apply_*|publish_*|trigger_*|rotate_*|dispatch_*|push_*|webhook*|infra_*|dotagent_exec|*",
        class: McpRpcClass::ExternalMutation,
        description: "Remote mutating/fetch PR/infra/webhook/exec RPCs and fail-closed default for unknown methods",
    },
];

const MUTATING_TOKENS: &[&str] = &[
    "create", "update", "delete", "remove", "destroy", "drop", "write", "edit", "patch", "put",
    "post", "push", "merge", "close", "reopen", "approve", "comment", "review", "deploy", "apply",
    "publish", "trigger", "rotate", "revoke", "grant", "set", "exec", "run", "send", "dispatch",
    "webhook", "mutate", "fetch",
];

const READONLY_EXACT_METHODS: &[&str] = &[
    "ping",
    "health",
    "status",
    "version",
    "search",
    "query",
    "list",
    "diff",
    "dotagent_read_file",
    "dotagent_search",
    "dotagent_status",
    "dotagent_submit_friction",
];

const READONLY_PREFIXES: &[&str] = &[
    "get_",
    "list_",
    "read_",
    "search_",
    "query_",
    "inspect_",
    "describe_",
    "explain_",
    "verify_",
    "diff_",
    "check_",
    "audit_",
    "lookup_",
];

const WORKSPACE_WRITE_EXACT: &[&str] = &["dotagent_edit_file"];

/// Splits an MCP method name on both non-alphanumeric delimiters and camelCase boundaries
/// (`get_and_deleteAll` -> `["get", "and", "delete", "all"]`, `read_deleteFile` -> `["read", "delete", "file"]`).
fn split_identifier_subtokens(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_lower_or_digit = false;
    for ch in raw.trim().chars() {
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            prev_lower_or_digit = false;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower_or_digit && !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
        cur.push(ch.to_ascii_lowercase());
        prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Deterministically classifies an `mcp__susanbdev__<sub_method>` or `mcp-gateway` tool name.
/// Unknown or compound (`get_and_delete`, `get_and_deleteAll`, `read_deleteFile`) methods fail
/// closed as `McpRpcClass::ExternalMutation`.
pub fn classify_mcp_sub_method(sub_method: &str) -> McpRpcClass {
    let lower = sub_method.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return McpRpcClass::ExternalMutation;
    }

    if WORKSPACE_WRITE_EXACT.contains(&lower.as_str()) {
        return McpRpcClass::WorkspaceWrite;
    }

    // Compound & camelCase smuggling guard: if ANY subtoken in the method identifier is a mutating
    // verb (e.g., `get_and_delete_repo`, `get_and_deleteAll`, `read_deleteFile`), fail closed!
    let subtokens = split_identifier_subtokens(sub_method);
    if subtokens
        .iter()
        .any(|seg| MUTATING_TOKENS.contains(&seg.as_str()))
    {
        return McpRpcClass::ExternalMutation;
    }

    if READONLY_EXACT_METHODS.contains(&lower.as_str())
        || READONLY_PREFIXES.iter().any(|p| lower.starts_with(p))
    {
        return McpRpcClass::ReadOnly;
    }

    // Fail-closed default for any unmodeled RPC verb!
    McpRpcClass::ExternalMutation
}

/// Evaluates declarative capability authorization for an MCP method under the active profile
/// and session taint state. Returns `Err((guard_code, detail, halt_session))` when denied.
pub fn authorize_mcp_rpc_invocation(
    full_tool_name: &str,
    sub_method: &str,
    writes_disabled: bool,
    session_tainted: bool,
    profile_id: &str,
) -> Result<McpRpcClass, (&'static str, String, bool)> {
    let class = classify_mcp_sub_method(sub_method);
    match class {
        McpRpcClass::ReadOnly => Ok(McpRpcClass::ReadOnly),
        McpRpcClass::WorkspaceWrite => {
            if writes_disabled {
                return Err((
                    "PROFILE_WRITE_TOOLS_DISABLED",
                    format!(
                        "Active runtime profile '{profile_id}' forbids workspace-mutating MCP tool '{full_tool_name}' (`enable_write_tools = false`)."
                    ),
                    false,
                ));
            }
            if session_tainted {
                return Err((
                    "TAINTED_EXTERNAL_MUTATION_BLOCKED",
                    format!(
                        "Tainted session cannot invoke workspace-write MCP tool '{full_tool_name}' (confused-deputy prevention)."
                    ),
                    true,
                ));
            }
            Ok(McpRpcClass::WorkspaceWrite)
        }
        McpRpcClass::ExternalMutation => {
            if writes_disabled {
                return Err((
                    "PROFILE_WRITE_TOOLS_DISABLED",
                    format!(
                        "Active runtime profile '{profile_id}' forbids mutating/unclassified MCP tool '{full_tool_name}' (`enable_write_tools = false`)."
                    ),
                    false,
                ));
            }
            if session_tainted {
                return Err((
                    "TAINTED_EXTERNAL_MUTATION_BLOCKED",
                    format!(
                        "Tainted session cannot invoke external-mutation MCP tool '{full_tool_name}' (confused-deputy prevention)."
                    ),
                    true,
                ));
            }
            Ok(McpRpcClass::ExternalMutation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_readonly_workspace_and_external_mutations_fail_closed() {
        assert_eq!(classify_mcp_sub_method("ping"), McpRpcClass::ReadOnly);
        assert_eq!(classify_mcp_sub_method("get_policy"), McpRpcClass::ReadOnly);
        assert_eq!(classify_mcp_sub_method("get_issue"), McpRpcClass::ReadOnly);
        assert_eq!(classify_mcp_sub_method("search"), McpRpcClass::ReadOnly);
        assert_eq!(
            classify_mcp_sub_method("dotagent_edit_file"),
            McpRpcClass::WorkspaceWrite
        );
        assert_eq!(
            classify_mcp_sub_method("write_file"),
            McpRpcClass::ExternalMutation
        );
        assert_eq!(
            classify_mcp_sub_method("fetch_url"),
            McpRpcClass::ExternalMutation
        );
        assert_eq!(
            classify_mcp_sub_method("update_issue"),
            McpRpcClass::ExternalMutation
        );
        // Compound & camelCase verb smuggling (`get_*` / `read_*` prefix + mutating verb) -> ExternalMutation!
        for smuggled in ["get_and_delete_pr", "get_and_deleteAll", "read_deleteFile"] {
            assert_eq!(
                classify_mcp_sub_method(smuggled),
                McpRpcClass::ExternalMutation,
                "failed on {smuggled}"
            );
        }
        // Unknown method -> fail-closed ExternalMutation!
        assert_eq!(
            classify_mcp_sub_method("reconfigure_mesh_fabric"),
            McpRpcClass::ExternalMutation
        );
    }

    #[test]
    fn enforces_taint_and_readonly_profile_gates() {
        // Read-only allowed even when tainted and writes_disabled
        assert!(
            authorize_mcp_rpc_invocation(
                "mcp__susanbdev__get_issue",
                "get_issue",
                true,
                true,
                "research-readonly"
            )
            .is_ok()
        );
        // Unknown / mutating blocked under read-only profile
        let err_ro = authorize_mcp_rpc_invocation(
            "mcp__susanbdev__update_issue",
            "update_issue",
            true,
            false,
            "research-readonly",
        )
        .expect_err("must block");
        assert_eq!(err_ro.0, "PROFILE_WRITE_TOOLS_DISABLED");

        // Local dotagent_edit_file AND remote mutating RPCs blocked under tainted session with halt=true
        let err_local_taint = authorize_mcp_rpc_invocation(
            "dotagent_edit_file",
            "dotagent_edit_file",
            false,
            true,
            "coding-agent",
        )
        .expect_err("must block tainted local edit");
        assert_eq!(err_local_taint.0, "TAINTED_EXTERNAL_MUTATION_BLOCKED");
        assert!(err_local_taint.2);

        for method in [
            "merge_pr",
            "write_file",
            "edit_file",
            "create_file",
            "patch_file",
        ] {
            let full = format!("mcp__susanbdev__{method}");
            let err_taint =
                authorize_mcp_rpc_invocation(&full, method, false, true, "coding-agent")
                    .expect_err("must block");
            assert_eq!(err_taint.0, "TAINTED_EXTERNAL_MUTATION_BLOCKED");
            assert!(err_taint.2);
        }
    }
}

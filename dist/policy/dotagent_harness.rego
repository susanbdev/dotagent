package susanbdev.dotagent.harness

import rego.v1

allowed_mcp_url := "https://mcp.zt.susanb.dev/mcp"
allowed_mcp_keys := {"url", "httpUrl", "type"}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    not is_object(cfg)
    msg := sprintf("MCP server '%s' entry must be a JSON object", [server_name])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    some k, _ in cfg
    not k in allowed_mcp_keys
    msg := sprintf("MCP server '%s' contains forbidden field '%s' (stdio/command/args/headers/upstream forbidden)", [server_name, k])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    t := object.get(cfg, "type", "http")
    t != "http"
    msg := sprintf("MCP server '%s' type '%v' is forbidden; only 'http' allowed", [server_name, t])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    u := object.get(cfg, "url", null)
    u != null
    u != allowed_mcp_url
    msg := sprintf("unapproved MCP server '%s' url '%v'", [server_name, u])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    hu := object.get(cfg, "httpUrl", null)
    hu != null
    hu != allowed_mcp_url
    msg := sprintf("unapproved MCP server '%s' httpUrl '%v'", [server_name, hu])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcpServers", {})
    is_object(cfg)
    object.get(cfg, "url", null) == null
    object.get(cfg, "httpUrl", null) == null
    msg := sprintf("MCP server '%s' missing mandatory pinned url/httpUrl", [server_name])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    not is_object(cfg)
    msg := sprintf("Codex TOML mcp_servers.%s entry must be a table", [server_name])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    some k, _ in cfg
    not k in allowed_mcp_keys
    msg := sprintf("Codex TOML mcp_servers.%s contains forbidden field '%s'", [server_name, k])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    u := object.get(cfg, "url", null)
    u != null
    u != allowed_mcp_url
    msg := sprintf("unapproved Codex TOML mcp_servers.%s URL '%v'", [server_name, u])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    hu := object.get(cfg, "httpUrl", null)
    hu != null
    hu != allowed_mcp_url
    msg := sprintf("unapproved Codex TOML mcp_servers.%s httpUrl '%v'", [server_name, hu])
}

deny contains msg if {
    some server_name, cfg in object.get(input, "mcp_servers", {})
    is_object(cfg)
    object.get(cfg, "url", null) == null
    object.get(cfg, "httpUrl", null) == null
    msg := sprintf("Codex TOML mcp_servers.%s missing mandatory pinned url", [server_name])
}

is_codex_config if object.get(input, "mcp_servers", null) != null
is_codex_config if object.get(input, "sandbox_mode", null) != null
is_codex_config if object.get(input, "approval_policy", null) != null
is_codex_config if object.get(input, "sandbox_workspace_write", null) != null
is_codex_config if object.get(input, "notify", null) != null
is_codex_config if object.get(input, "shell_environment_policy", null) != null
is_codex_config if object.get(input, "project_doc_max_bytes", null) != null
is_codex_config if object.get(input, "model_auto_compact_token_limit", null) != null

deny contains msg if {
    is_codex_config
    object.get(input, "sandbox_mode", "") != "workspace-write"
    msg := "Codex sandbox_mode must equal 'workspace-write'"
}

deny contains msg if {
    is_codex_config
    object.get(input, "approval_policy", "on-request") == "never"
    msg := "Codex approval_policy 'never' is forbidden"
}

deny contains msg if {
    is_codex_config
    object.get(input, "notify", []) != ["agent-guard", "on-stop"]
    msg := "Codex notify hook must equal ['agent-guard', 'on-stop']"
}

deny contains msg if {
    is_codex_config
    object.get(input, "sandbox_workspace_write", null) == null
    msg := "Codex configuration missing mandatory [sandbox_workspace_write] section"
}

deny contains msg if {
    sbx := object.get(input, "sandbox_workspace_write", null)
    sbx != null
    object.get(sbx, "network_access", true) != false
    msg := "Codex sandbox_workspace_write.network_access must be false"
}

deny contains msg if {
    sbx := object.get(input, "sandbox_workspace_write", null)
    sbx != null
    object.get(sbx, "exclude_slash_tmp", false) != true
    msg := "Codex sandbox_workspace_write.exclude_slash_tmp must be true"
}

deny contains msg if {
    some rule in object.get(object.get(input, "permissions", {}), "allow", [])
    contains(rule, "*")
    msg := sprintf("wildcard permission allowlist entry '%s' is forbidden", [rule])
}

deny contains msg if {
    object.get(input, "autoMemoryEnabled", false) == true
    msg := "autoMemoryEnabled must be false to prevent cross-session cache bleed"
}

deny contains msg if {
    object.get(input, "disableAllHooks", false) == true
    msg := "disableAllHooks must be false so agent-guard hooks cannot be disabled"
}

deny contains msg if {
    auth := object.get(input, "authority", null)
    auth != null
    object.get(auth, "root_file", "") != "AGENTS.md"
    msg := "profile authority.root_file must equal AGENTS.md"
}

deny contains msg if {
    git_cfg := object.get(input, "git", null)
    git_cfg != null
    object.get(git_cfg, "hooks_path", "") != "/dev/null"
    msg := "profile git.hooks_path must equal /dev/null"
}

deny contains msg if {
    trav := object.get(input, "traversal", null)
    trav != null
    object.get(input, "role", "") != "investigator"
    object.get(trav, "max_directory_walk_depth", 2) > 2
    msg := "non-investigator profile traversal.max_directory_walk_depth must be <= 2"
}

deny contains msg if {
    trav := object.get(input, "traversal", null)
    trav != null
    object.get(input, "role", "") == "investigator"
    object.get(trav, "max_directory_walk_depth", 20) > 20
    msg := "investigator profile traversal.max_directory_walk_depth must be <= 20"
}

deny contains msg if {
    trav := object.get(input, "traversal", null)
    trav != null
    object.get(trav, "max_reference_pointer_levels", 2) > 2
    msg := "profile traversal.max_reference_pointer_levels must be <= 2"
}

deny contains msg if {
    some prof in object.get(input, "profiles", [])
    object.get(object.get(prof, "git", {}), "hooks_path", "") != "/dev/null"
    msg := sprintf("compiled profile '%s' violates git.hooks_path=/dev/null", [object.get(prof, "profile_id", "<unknown>")])
}

forbidden_workflow_triggers := {"workflow_run", "workflow_call", "repository_dispatch"}

deny contains msg if {
    some trigger in forbidden_workflow_triggers
    on_cfg := object.get(object.get(input, "workflow", {}), "on", {})
    object.get(on_cfg, trigger, null) != null
    msg := sprintf("chained GitHub Actions trigger '%s' is strictly forbidden", [trigger])
}

package susanbdev.dotagent.harness

import rego.v1

allowed_mcp_url := "https://mcp.zt.susanb.dev/mcp"

deny contains msg if {
    some server_name, cfg in input.mcpServers
    url := object.get(cfg, "url", object.get(cfg, "httpUrl", ""))
    url != allowed_mcp_url
    msg := sprintf("unapproved MCP server '%s' URL '%s'", [server_name, url])
}

deny contains msg if {
    some server_name, cfg in input.mcpServers
    object.get(cfg, "command", "") != ""
    msg := sprintf("stdio/npx MCP server '%s' is forbidden; only HTTPS susanbdev/mcp allowed", [server_name])
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

forbidden_workflow_triggers := {"workflow_run", "workflow_call", "repository_dispatch"}

deny contains msg if {
    some trigger in forbidden_workflow_triggers
    on_cfg := object.get(object.get(input, "workflow", {}), "on", {})
    object.get(on_cfg, trigger, null) != null
    msg := sprintf("chained GitHub Actions trigger '%s' is strictly forbidden", [trigger])
}

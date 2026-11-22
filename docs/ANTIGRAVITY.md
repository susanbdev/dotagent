# Native Antigravity workspace hooks

`dotagent-compiler` generates and verifies `dist/antigravity/hooks.json` as part of the normal bundle. Google Antigravity App, CLI, and IDE discover the installed workspace file at `.agents/hooks.json`. [Google hook specification](https://antigravity.google/docs/hooks)

## Workspace activation

Use a verified dotagent bundle and its installed binaries. Give `--workspace` the absolute, canonical root of the workspace opened in Antigravity.

```sh
dotagent activate --antigravity --workspace "$PWD" --dotagent-root "$BUNDLE" --bin-dir "$BIN_DIR" --dry-run
dotagent activate --antigravity --workspace "$PWD" --dotagent-root "$BUNDLE" --bin-dir "$BIN_DIR"
dotagent deactivate --antigravity --workspace "$PWD"
```

Activation verifies the bundle's hook template, pins the validated guard executable and workspace by absolute path, and merges the `dotagent` group with the existing configuration. It keeps a local activation journal with the original bytes and permissions for recovery. Deactivation uses the existing operator authorization, restores the original file when possible, and preserves unrelated groups added after activation. The workspace route requires no global Git installation.

If an external change removes the managed group from a changed file, deactivation reports the conflict and preserves both the current configuration and the recovery journal. An already-restored file can be recognized by its exact saved bytes and permissions.

An installed `PreToolUse` entry looks like this excerpt. Start a fresh Antigravity session after activation and inspect `/hooks` in the CLI. [CLI reference](https://antigravity.google/docs/cli/reference/)

```json
{
  "dotagent": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [{
          "type": "command",
          "command": "'/opt/dotagent/bin/agent-guard' antigravity-hook PreToolUse --workspace '/srv/project'",
          "timeout": 10
        }]
      }
    ]
  }
}
```

## Coverage

| Event or operation | Dotagent behavior |
| --- | --- |
| `PreToolUse` | Verifies the conversation and the exact single workspace, then sends supported tool calls to the shared Rust guard. Malformed requests, unknown tools, and multiple workspaces fail closed with a JSON denial. |
| `run_command` | Rewrites only `CommandLine` to use the absolute, installed guard. The existing sandbox checks the proposed command and enforces Landlock or Seatbelt where available. The rewritten command refuses to run when kernel confinement is unavailable. |
| `view_file` | Runs the existing path, content, and budget checks on the entire file before allowing a native read. Large files whose authorization requires a slice rewrite must be read through a guarded shell command. Google's hook reference leaves native slice indexing unspecified. |
| Native writes | `write_to_file`, `replace_file_content`, and `multi_replace_file_content` use existing write and content checks. Artifact-directory writes and edits under `.agents/` are blocked. |
| Search and listing | `list_dir` checks the requested directory. `find_by_name` requires an explicit depth within the existing walk limit. `grep_search` checks an explicit regular file because the host's request has no directory-depth parameter. Host-rendered results are outside the hook response contract. |
| `SessionStart` | Loads or initializes the existing conversation ledger without clearing a previously halted conversation. |
| `PostToolUse` | Records tool and status through the existing audit channel. The native envelope exposes an optional error string and supplies no tool result to sanitize or replace. |
| `PreInvocation`, `PostInvocation` | A halted ledger can terminate further model invocation. Antigravity may invoke these events during automatic re-entry, so they never reset the ledger as if a fresh user prompt had arrived. |
| `Stop` | Checks the ledger and workspace audit gates when fully idle and records the result. The hook allows the lifecycle to finish and does not issue a signed StopReceipt. |

The adapter writes a single JSON response to stdout and exits zero on a denial. Google documents that the host ignores failed hooks. A missing or timed-out hook can therefore leave tool execution to the host's own policy. Native file decisions are pre-dispatch checks. They do not supply kernel confinement or a post-dispatch output filter. Workspace hooks and the absolute binary must remain enabled and available to the host. [Hook failure behavior](https://antigravity.google/docs/build-plugins/#lifecycle-hooks)

Google-managed Remote Agents run in a separate environment. Their workspace hook loading and enforcement require fresh live verification. Use `/hooks` on the intended host to confirm the exact installed group and exercise an allowed operation and a denied operation before relying on interception. [Remote Agents](https://antigravity.google/docs/remote-agents)

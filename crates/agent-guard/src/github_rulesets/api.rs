use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::github_governance::{
    COPILOT_GATE_CONTEXT, GITHUB_ACTIONS_INTEGRATION_ID, dotagent_required_checks,
};
use crate::json::JsonValue;

use super::Args;

const API_TIMEOUT: Duration = Duration::from_secs(45);
const PROMOTER_VARIABLE: &str = "PROMOTER_APP_ID";
const PROMOTER_SECRET: &str = "PROMOTER_APP_PRIVATE_KEY";

pub(super) trait Api {
    fn get(&self, endpoint: &str) -> Result<JsonValue, String>;
    fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String>;
    fn write(&self, method: &str, endpoint: &str, payload: &JsonValue)
    -> Result<JsonValue, String>;
}

pub(super) struct GhApi {
    gh: PathBuf,
}

impl GhApi {
    pub(super) fn new() -> Result<Self, String> {
        let gh = crate::feedback_loop::resolve_gh_bin();
        if !gh.is_absolute() || !crate::coordinator::is_trusted_executable_file(&gh) {
            return Err("trusted GitHub CLI executable unavailable".to_string());
        }
        Ok(Self { gh })
    }

    fn call(
        &self,
        method: &str,
        endpoint: &str,
        options: &[&str],
        payload: Option<&JsonValue>,
    ) -> Result<String, String> {
        let fail = |error: &dyn std::fmt::Display| format!("{method} {endpoint}: {error}");
        if !(endpoint.starts_with("repos/") || endpoint.starts_with("orgs/"))
            || endpoint.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(format!("{method}: invalid GitHub ruleset endpoint"));
        }
        let mut cmd = Command::new(&self.gh);
        cmd.env_clear();
        for name in [
            "HOME",
            "USERPROFILE",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "APPDATA",
            "LOCALAPPDATA",
            "SYSTEMROOT",
            "GH_CONFIG_DIR",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.env(
            "PATH",
            "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/opt/antigravity/bin",
        )
        .env("GH_PROMPT_DISABLED", "1")
        .env("NO_COLOR", "1")
        .args([
            "api",
            "--hostname",
            "github.com",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            "--method",
            method,
            endpoint,
        ])
        .args(options)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let input = payload.map(JsonValue::to_json_string);
        if input.is_some() {
            cmd.args(["--input", "-"]).stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|err| fail(&err))?;
        let reader = |pipe: Box<dyn Read + Send>| {
            thread::spawn(move || -> std::io::Result<Vec<u8>> {
                let mut bytes = Vec::new();
                let mut pipe = pipe;
                pipe.read_to_end(&mut bytes)?;
                Ok(bytes)
            })
        };
        let output = child.stdout.take().ok_or_else(|| fail(&"missing stdout"))?;
        let errors = child.stderr.take().ok_or_else(|| fail(&"missing stderr"))?;
        let stdout = reader(Box::new(output));
        let stderr = reader(Box::new(errors));
        let writer = if let Some(input) = input {
            let mut pipe = child.stdin.take().ok_or_else(|| fail(&"missing stdin"))?;
            Some(thread::spawn(move || pipe.write_all(input.as_bytes())))
        } else {
            None
        };
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < API_TIMEOUT => {
                    thread::sleep(Duration::from_millis(20));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return match result {
                        Err(err) => Err(fail(&err)),
                        _ => Err(fail(&"GitHub CLI request timed out")),
                    };
                }
            }
        };
        let read = |handle: thread::JoinHandle<std::io::Result<Vec<u8>>>| {
            handle
                .join()
                .map_err(|_| fail(&"could not collect GitHub CLI response"))?
                .map_err(|err| fail(&err))
        };
        let error_bytes = read(stderr)?;
        let output_bytes = read(stdout)?;
        if !status.success() {
            let message = String::from_utf8_lossy(&error_bytes);
            return if message.trim().is_empty() {
                Err(fail(&status))
            } else {
                Err(fail(&message.trim()))
            };
        }
        if let Some(writer) = writer {
            writer
                .join()
                .map_err(|_| fail(&"could not send GitHub CLI request"))?
                .map_err(|err| fail(&err))?;
        }
        String::from_utf8(output_bytes).map_err(|err| fail(&err))
    }
}

impl Api for GhApi {
    fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
        let raw = self.call("GET", endpoint, &[], None)?;
        JsonValue::parse(&raw).map_err(|err| format!("GET {endpoint}: invalid JSON: {err}"))
    }

    fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String> {
        let jq = format!("{selector} | @json");
        let raw = self.call("GET", endpoint, &["--paginate", "--jq", &jq], None)?;
        raw.lines()
            .map(|line| {
                JsonValue::parse(line)
                    .map_err(|err| format!("GET {endpoint}: invalid paginated JSON item: {err}"))
            })
            .collect()
    }

    fn write(
        &self,
        method: &str,
        endpoint: &str,
        payload: &JsonValue,
    ) -> Result<JsonValue, String> {
        if !matches!(method, "POST" | "PUT") {
            return Err(format!("unsupported ruleset write method '{method}'"));
        }
        let raw = self.call(method, endpoint, &[], Some(payload))?;
        JsonValue::parse(&raw).map_err(|err| format!("{method} {endpoint}: invalid JSON: {err}"))
    }
}

fn encode_url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn verify_pr_checks(
    api: &impl Api,
    repo: &str,
    default: &str,
    proof: Option<u64>,
) -> Result<(), String> {
    let slug = repo
        .strip_prefix("repos/")
        .ok_or_else(|| "invalid repository endpoint".to_string())?;
    let number = match proof {
        Some(number) => number,
        None => {
            let base = encode_url_component(default);
            let pulls = api.items(
                &format!(
                    "{repo}/pulls?state=closed&base={base}&sort=updated&direction=desc&per_page=100"
                ),
                ".[]",
            )?;
            pulls
                .iter()
                .filter_map(|pr| {
                    Some((pr.get("merged_at")?.as_str()?, pr.get("number")?.as_u64()?))
                })
                .max()
                .map(|(_, number)| number)
                .ok_or_else(|| {
                    "no merged default-branch PR; supply --proof-pr NUMBER".to_string()
                })?
        }
    };
    let pr = api.get(&format!("{repo}/pulls/{number}"))?;
    let base = pr.get("base");
    let head = pr
        .get("head")
        .and_then(|head| head.get("sha"))
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let ready = pr.get("draft").and_then(JsonValue::as_bool) != Some(true)
        && (pr.get("state").and_then(JsonValue::as_str) == Some("open")
            || pr.get("merged").and_then(JsonValue::as_bool) == Some(true));
    let valid_head = head.len() == 40
        && head
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ready
        || !valid_head
        || base
            .and_then(|base| base.get("ref"))
            .and_then(JsonValue::as_str)
            != Some(default)
        || !base
            .and_then(|base| base.get("repo"))
            .and_then(|repo| repo.get("full_name"))
            .and_then(JsonValue::as_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(slug))
    {
        return Err(format!(
            "PR #{number} must be open and ready or merged, targeting {slug}:{default}"
        ));
    }

    let checks = api.items(
        &format!("{repo}/commits/{head}/check-runs?filter=all&per_page=100"),
        ".check_runs[]",
    )?;
    let mut latest_runs = BTreeMap::<&str, (u64, &JsonValue)>::new();
    for run in &checks {
        if run
            .get("app")
            .and_then(|app| app.get("id"))
            .and_then(JsonValue::as_u64)
            != Some(GITHUB_ACTIONS_INTEGRATION_ID)
        {
            continue;
        }
        let Some(name) = run.get("name").and_then(JsonValue::as_str) else {
            continue;
        };
        let Some(id) = run.get("id").and_then(JsonValue::as_u64) else {
            continue;
        };
        if latest_runs
            .get(name)
            .is_none_or(|(current, _)| id > *current)
        {
            latest_runs.insert(name, (id, run));
        }
    }
    let statuses = api.items(
        &format!("{repo}/commits/{head}/statuses?per_page=100"),
        ".[]",
    )?;
    // GitHub returns commit statuses in reverse chronological order.
    let latest_gate = statuses.iter().find(|status| {
        status.get("context").and_then(JsonValue::as_str) == Some(COPILOT_GATE_CONTEXT)
    });
    let missing: Vec<&str> = dotagent_required_checks()
        .filter(|&name| {
            if name == COPILOT_GATE_CONTEXT {
                !latest_gate.is_some_and(|status| {
                    status.get("state").and_then(JsonValue::as_str) == Some("success")
                        && status
                            .get("creator")
                            .and_then(|creator| creator.get("login"))
                            .and_then(JsonValue::as_str)
                            == Some("github-actions[bot]")
                })
            } else {
                !latest_runs.get(name).is_some_and(|(_, run)| {
                    run.get("status").and_then(JsonValue::as_str) == Some("completed")
                        && run.get("conclusion").and_then(JsonValue::as_str) == Some("success")
                })
            }
        })
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "PR #{number} ({head}) lacks green trusted checks: {}",
            missing.join(", ")
        ));
    }
    println!("Verified PR #{number} checks on {head}");
    Ok(())
}

pub(super) fn verify_repo_readiness(api: &impl Api, args: &Args, repo: &str) -> Result<(), String> {
    let details = api.get(repo)?;
    if details.get("archived").and_then(JsonValue::as_bool) == Some(true)
        || details
            .get("allow_squash_merge")
            .and_then(JsonValue::as_bool)
            != Some(true)
    {
        return Err(format!(
            "{repo}: enable squash merges on an active repository before applying"
        ));
    }
    if args.is_dotagent() {
        let default = details
            .get("default_branch")
            .and_then(JsonValue::as_str)
            .filter(|branch| !branch.is_empty())
            .ok_or_else(|| format!("{repo}: missing default branch"))?;
        let branch = encode_url_component(default);
        let rules = api.items(
            &format!("{repo}/rules/branches/{branch}?per_page=100"),
            ".[]",
        )?;
        if rules
            .iter()
            .any(|rule| rule.get("type").and_then(JsonValue::as_str) == Some("merge_queue"))
        {
            return Err(format!(
                "{repo}: the effective native merge queue needs merge_group checks"
            ));
        }
        verify_pr_checks(api, repo, default, args.proof_pr)?;
    }
    Ok(())
}

fn release_setting(
    api: &impl Api,
    repo: &str,
    group: &str,
    name: &str,
) -> Result<JsonValue, String> {
    match api.get(&format!("{repo}/environments/release/{group}/{name}")) {
        Err(error)
            if error.lines().any(|line| {
                let line = line.trim();
                line == "HTTP 404" || line.ends_with("(HTTP 404)")
            }) =>
        {
            api.get(&format!("{repo}/actions/{group}/{name}"))
        }
        result => result,
    }
}

pub(super) fn verify_release_settings(
    api: &impl Api,
    repo: &str,
    app_id: u64,
) -> Result<(), String> {
    let env = api.get(&format!("{repo}/environments/release"))?;
    let reviewers_configured = env
        .get("protection_rules")
        .and_then(JsonValue::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|rule| {
                rule.get("type").and_then(JsonValue::as_str) == Some("required_reviewers")
                    && rule
                        .get("reviewers")
                        .and_then(JsonValue::as_array)
                        .is_some_and(|reviewers| !reviewers.is_empty())
            })
        });
    if !reviewers_configured {
        return Err("release environment requires at least one configured reviewer".to_string());
    }
    let variable = release_setting(api, repo, "variables", PROMOTER_VARIABLE)?;
    if variable.get("value").and_then(JsonValue::as_str) != Some(app_id.to_string().as_str()) {
        return Err(format!(
            "{PROMOTER_VARIABLE} does not match --promoter-app-id"
        ));
    }
    let metadata = release_setting(api, repo, "secrets", PROMOTER_SECRET)?;
    if metadata.get("name").and_then(JsonValue::as_str) != Some(PROMOTER_SECRET) {
        return Err(format!("missing {PROMOTER_SECRET} metadata"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "repos/susanbdev/dotagent";
    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

    #[derive(Default)]
    struct FixtureApi {
        responses: BTreeMap<String, Result<JsonValue, String>>,
    }

    impl FixtureApi {
        fn respond(&mut self, endpoint: &str, raw: &str) {
            self.responses.insert(
                format!("{REPO}/{endpoint}"),
                Ok(JsonValue::parse(raw).expect("valid fixture JSON")),
            );
        }

        fn check_fixture(&mut self, checks: Vec<JsonValue>, statuses: &str) {
            self.responses.insert(
                format!("{REPO}/commits/{HEAD}/check-runs?filter=all&per_page=100"),
                Ok(JsonValue::Array(checks)),
            );
            self.respond(&format!("commits/{HEAD}/statuses?per_page=100"), statuses);
        }
    }

    impl Api for FixtureApi {
        fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
            self.responses
                .get(endpoint)
                .unwrap_or_else(|| panic!("unexpected fixture request: {endpoint}"))
                .clone()
        }

        fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String> {
            let expected = if endpoint.contains("/check-runs?") {
                ".check_runs[]"
            } else {
                ".[]"
            };
            assert_eq!(selector, expected);
            let JsonValue::Array(items) = self.get(endpoint)? else {
                panic!("expected paginated fixture items")
            };
            Ok(items)
        }

        fn write(&self, _: &str, _: &str, _: &JsonValue) -> Result<JsonValue, String> {
            panic!("readiness preflights never write");
        }
    }

    fn check(name: &str, id: u64, app: u64, conclusion: &str) -> JsonValue {
        JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str(name.to_string())),
            ("id".to_string(), JsonValue::Uint(id)),
            (
                "app".to_string(),
                JsonValue::Object(vec![("id".to_string(), JsonValue::Uint(app))]),
            ),
            (
                "status".to_string(),
                JsonValue::Str("completed".to_string()),
            ),
            (
                "conclusion".to_string(),
                JsonValue::Str(conclusion.to_string()),
            ),
        ])
    }

    #[test]
    fn proof_requires_the_newest_merge_and_latest_trusted_exact_head_evidence() {
        let mut api = FixtureApi::default();
        api.respond(
            "pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100",
            r#"[
            {"number":5,"merged_at":"2026-11-01T10:00:00Z"},
            {"number":7,"merged_at":null},
            {"number":6,"merged_at":"2026-11-02T10:00:00Z"}
        ]"#,
        );
        api.respond("pulls/6", &format!(r#"{{"state":"closed","merged":true,"head":{{"sha":"{HEAD}"}},"base":{{"ref":"main","repo":{{"full_name":"susanbdev/dotagent"}}}}}}"#));

        let mut checks: Vec<_> = dotagent_required_checks()
            .filter(|&name| name != COPILOT_GATE_CONTEXT)
            .map(|name| check(name, 1, GITHUB_ACTIONS_INTEGRATION_ID, "success"))
            .collect();
        let required = dotagent_required_checks().next().expect("CI check");
        checks.push(check(required, 3, GITHUB_ACTIONS_INTEGRATION_ID, "failure"));
        checks.push(check(
            required,
            4,
            GITHUB_ACTIONS_INTEGRATION_ID + 1,
            "success",
        ));
        let green_gate = r#"[{"context":"Ring-0 & Copilot Gate","state":"success","creator":{"login":"github-actions[bot]"}}]"#;
        api.check_fixture(checks.clone(), green_gate);
        let failure =
            verify_pr_checks(&api, REPO, "main", None).expect_err("newest trusted failure wins");
        assert!(failure.contains("PR #6") && failure.contains(HEAD) && failure.contains(required));

        checks.push(check(required, 5, GITHUB_ACTIONS_INTEGRATION_ID, "success"));
        let spoofed_gate = r#"[
            {"context":"Ring-0 & Copilot Gate","state":"success","creator":{"login":"other-app[bot]"}},
            {"context":"Ring-0 & Copilot Gate","state":"success","creator":{"login":"github-actions[bot]"}}
        ]"#;
        api.check_fixture(checks.clone(), spoofed_gate);
        let failure = verify_pr_checks(&api, REPO, "main", Some(6))
            .expect_err("latest status creator matters");
        assert!(failure.ends_with(COPILOT_GATE_CONTEXT));

        api.check_fixture(checks, green_gate);
        verify_pr_checks(&api, REPO, "main", None).expect("all exact-head evidence is green");
    }

    #[test]
    fn release_settings_only_fall_back_for_http_not_found() {
        let mut api = FixtureApi::default();
        api.respond(
            "environments/release",
            r#"{"protection_rules":[{"type":"required_reviewers","reviewers":[{"id":42}]}]}"#,
        );
        let environment_variable =
            format!("{REPO}/environments/release/variables/{PROMOTER_VARIABLE}");
        api.responses.insert(
            environment_variable.clone(),
            Err("gh: Not Found (HTTP 404)".into()),
        );
        api.respond("actions/variables/PROMOTER_APP_ID", r#"{"value":"42"}"#);
        api.respond(
            "environments/release/secrets/PROMOTER_APP_PRIVATE_KEY",
            r#"{"name":"PROMOTER_APP_PRIVATE_KEY"}"#,
        );
        verify_release_settings(&api, REPO, 42).expect("404 may use the repository variable");

        api.responses.insert(
            environment_variable,
            Err("gh: HTTP 404 in error body (HTTP 403)".into()),
        );
        assert!(
            verify_release_settings(&api, REPO, 42)
                .expect_err("403 must fail closed")
                .ends_with("(HTTP 403)")
        );
    }
}

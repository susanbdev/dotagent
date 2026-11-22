use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::github_governance::{
    COPILOT_GATE_CONTEXT, GITHUB_ACTIONS_INTEGRATION_ID, dotagent_required_checks,
    validate_github_ident,
};
use crate::json::JsonValue;

use super::{Args, Scope};

const API_TIMEOUT: Duration = Duration::from_secs(45);
const COPILOT_REVIEWER_ID: u64 = 175_728_472;
const GITHUB_ACTIONS_BOT_ID: u64 = 41_898_282;
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
        if !(endpoint.starts_with("repos/")
            || endpoint.starts_with("orgs/")
            || (method == "GET" && endpoint == "user"))
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
        .stderr(Stdio::null());
        let input = payload.map(JsonValue::to_json_string);
        if input.is_some() {
            cmd.args(["--input", "-"]).stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|err| fail(&err))?;
        let mut output = child.stdout.take().ok_or_else(|| fail(&"missing stdout"))?;
        let stdout = thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes)?;
            Ok(bytes)
        });
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
        let output_bytes = stdout
            .join()
            .map_err(|_| fail(&"could not collect GitHub CLI response"))?
            .map_err(|err| fail(&err))?;
        if !status.success() {
            if options.contains(&"--include")
                && let Ok(response) = std::str::from_utf8(&output_bytes)
                && let Some((code, _)) = split_http_response(response)
                && code >= 400
            {
                return Err(fail(&format_args!("HTTP {code}")));
            }
            return Err(fail(&format_args!("GitHub CLI failed ({status})")));
        }
        if let Some(writer) = writer {
            writer
                .join()
                .map_err(|_| fail(&"could not send GitHub CLI request"))?
                .map_err(|err| fail(&err))?;
        }
        let raw = String::from_utf8(output_bytes).map_err(|err| fail(&err))?;
        if options.contains(&"--include") {
            let (code, body) = split_http_response(&raw)
                .ok_or_else(|| fail(&"missing GitHub API HTTP response metadata"))?;
            if !(200..300).contains(&code) {
                return Err(fail(&format_args!("HTTP {code}")));
            }
            return Ok(body.to_string());
        }
        Ok(raw)
    }
}

// `gh api --include` prints the HTTP status line and response headers before the body.
fn split_http_response(raw: &str) -> Option<(u16, &str)> {
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))?;
    let mut status = headers.lines().next()?.split_ascii_whitespace();
    if !matches!(
        status.next()?,
        "HTTP/1.0" | "HTTP/1.1" | "HTTP/2.0" | "HTTP/3.0"
    ) {
        return None;
    }
    let code = status.next()?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((code.parse().ok()?, body))
}

impl Api for GhApi {
    fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
        let raw = self.call("GET", endpoint, &["--include"], None)?;
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
        let raw = self.call(method, endpoint, &["--include"], Some(payload))?;
        JsonValue::parse(&raw).map_err(|err| format!("{method} {endpoint}: invalid JSON: {err}"))
    }
}

pub(super) fn encode_url_component(value: &str) -> String {
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

fn positive_id(value: &JsonValue) -> Option<u64> {
    match value.get("id")? {
        JsonValue::Uint(id) if *id > 0 => Some(*id),
        JsonValue::Int(id) if *id > 0 => u64::try_from(*id).ok(),
        _ => None,
    }
}

fn has_string(value: &JsonValue, key: &str, expected: &str) -> bool {
    value.get(key).and_then(JsonValue::as_str) == Some(expected)
}

fn has_bool(value: &JsonValue, key: &str, expected: bool) -> bool {
    value.get(key).and_then(JsonValue::as_bool) == Some(expected)
}

fn valid_account_login(login: &str) -> bool {
    validate_github_ident(login).is_ok()
        && !login.contains('.')
        && login
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

pub(super) fn verify_apply_authority(
    api: &impl Api,
    scope: &Scope,
) -> Result<(String, u64, u64), String> {
    let user = api.get("user")?;
    let (login, id) = user
        .get("login")
        .and_then(JsonValue::as_str)
        .filter(|login| valid_account_login(login) && has_string(&user, "type", "User"))
        .zip(positive_id(&user))
        .ok_or_else(|| "GitHub authentication must identify a user account".to_string())?;
    let path = scope.owner_path();
    let scope_id = match scope {
        Scope::Repo(slug) => {
            let details = api.get(&path)?;
            if !has_string(&details, "full_name", slug)
                || !details
                    .get("permissions")
                    .is_some_and(|permissions| has_bool(permissions, "admin", true))
            {
                return Err(format!("{path}: exact repository admin authority required"));
            }
            positive_id(&details).ok_or_else(|| format!("{path}: missing repository ID"))?
        }
        Scope::Org(org) => {
            let membership = api.get(&format!("{path}/memberships/{login}"))?;
            let organization = membership.get("organization");
            if !has_string(&membership, "state", "active")
                || !has_string(&membership, "role", "admin")
                || !organization.is_some_and(|organization| has_string(organization, "login", org))
                || !membership.get("user").is_some_and(|member| {
                    has_string(member, "login", login) && positive_id(member) == Some(id)
                })
            {
                return Err(format!(
                    "{path}: active organization admin authority required"
                ));
            }
            organization
                .and_then(positive_id)
                .ok_or_else(|| format!("{path}: missing organization ID"))?
        }
    };
    let permissions = api.get(&format!("{path}/actions/permissions/workflow"))?;
    if !has_bool(&permissions, "can_approve_pull_request_reviews", false) {
        return Err(format!(
            "{path}: GitHub Actions must have pull-request approval disabled"
        ));
    }
    Ok((login.to_string(), id, scope_id))
}

#[derive(Debug, PartialEq, Eq)]
struct ProofPr<'a> {
    head: &'a str,
    base: &'a str,
    merged: bool,
}

fn git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn proof_pr<'a>(
    pr: &'a JsonValue,
    number: u64,
    slug: &str,
    repo_id: u64,
    default: &str,
) -> Option<ProofPr<'a>> {
    let merged = pr.get("merged")?.as_bool()?;
    let state = if merged { "closed" } else { "open" };
    let base = pr.get("base")?;
    let base_repo = base.get("repo")?;
    if pr.get("number")?.as_u64()? != number
        || !has_string(pr, "state", state)
        || !has_bool(pr, "draft", false)
        || !has_string(base, "ref", default)
        || !has_string(base_repo, "full_name", slug)
        || positive_id(base_repo) != Some(repo_id)
    {
        return None;
    }
    let head = pr.get("head")?.get("sha")?.as_str()?;
    let base = base.get("sha")?.as_str()?;
    (git_sha(head) && git_sha(base)).then_some(ProofPr { head, base, merged })
}

fn is_bot(user: &JsonValue, login: &str, id: u64) -> bool {
    has_string(user, "type", "Bot")
        && has_string(user, "login", login)
        && positive_id(user) == Some(id)
}

fn verify_copilot_review(api: &impl Api, pr: &str, head: &str) -> Result<(), String> {
    let reviews = api.items(&format!("{pr}/reviews?per_page=100"), ".[]")?;
    let mut latest = None;
    for review in &reviews {
        if !has_string(review, "commit_id", head)
            || !review.get("user").is_some_and(|user| {
                is_bot(
                    user,
                    "copilot-pull-request-reviewer[bot]",
                    COPILOT_REVIEWER_ID,
                )
            })
        {
            continue;
        }
        let id = positive_id(review)
            .ok_or_else(|| format!("{pr}: malformed exact-head Copilot review"))?;
        if latest.is_none_or(|(current, _)| id > current) {
            latest = Some((id, review));
        }
    }
    let (id, review) = latest.ok_or_else(|| format!("{pr}: missing Copilot review on {head}"))?;
    if !matches!(
        review.get("state").and_then(JsonValue::as_str),
        Some("APPROVED" | "COMMENTED")
    ) || !review
        .get("submitted_at")
        .and_then(JsonValue::as_str)
        .is_some_and(|date| !date.is_empty())
    {
        return Err(format!(
            "{pr}: latest Copilot review on {head} is not clean"
        ));
    }
    let comments = api.items(&format!("{pr}/reviews/{id}/comments?per_page=100"), ".[]")?;
    if !comments.is_empty() {
        return Err(format!(
            "{pr}: latest Copilot review on {head} has inline findings"
        ));
    }
    Ok(())
}

fn verify_pr_checks(
    api: &impl Api,
    repo: &str,
    repo_id: u64,
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
                    let merged = pr.get("merged_at")?.as_str()?;
                    let number = pr.get("number")?.as_u64()?;
                    (!merged.is_empty() && number > 0).then_some((merged, number))
                })
                .max()
                .map(|(_, number)| number)
                .ok_or_else(|| {
                    "no merged default-branch PR; supply --proof-pr NUMBER".to_string()
                })?
        }
    };
    let endpoint = format!("{repo}/pulls/{number}");
    let pr = api.get(&endpoint)?;
    let original = proof_pr(&pr, number, slug, repo_id, default).ok_or_else(|| {
        format!("PR #{number} must be open and ready or merged, targeting {slug}:{default}")
    })?;
    let head = original.head;

    let checks = api.items(
        &format!("{repo}/commits/{head}/check-runs?filter=all&per_page=100"),
        ".check_runs[]",
    )?;
    let mut latest_runs = BTreeMap::<&str, (u64, &JsonValue)>::new();
    for run in &checks {
        if run.get("app").and_then(positive_id) != Some(GITHUB_ACTIONS_INTEGRATION_ID) {
            continue;
        }
        let Some(name) = run.get("name").and_then(JsonValue::as_str) else {
            continue;
        };
        if !dotagent_required_checks().any(|required| required == name) {
            continue;
        }
        let id = positive_id(run).ok_or_else(|| {
            format!("PR #{number} ({head}) has malformed Actions evidence for {name}")
        })?;
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
                    has_string(status, "state", "success")
                        && status.get("creator").is_some_and(|creator| {
                            is_bot(creator, "github-actions[bot]", GITHUB_ACTIONS_BOT_ID)
                        })
                })
            } else {
                !latest_runs.get(name).is_some_and(|(_, run)| {
                    has_string(run, "head_sha", head)
                        && has_string(run, "status", "completed")
                        && has_string(run, "conclusion", "success")
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
    verify_copilot_review(api, &endpoint, head)?;
    let current = api.get(&endpoint)?;
    if proof_pr(&current, number, slug, repo_id, default).as_ref() != Some(&original) {
        return Err(format!(
            "PR #{number} changed during exact-head readiness checks"
        ));
    }
    let current_repo = api.get(repo)?;
    if !has_string(&current_repo, "full_name", slug)
        || !has_string(&current_repo, "default_branch", default)
        || positive_id(&current_repo) != Some(repo_id)
        || !has_bool(&current_repo, "allow_squash_merge", true)
        || !has_bool(&current_repo, "archived", false)
    {
        return Err(format!(
            "{repo}: repository or default branch changed during readiness checks"
        ));
    }
    println!("Verified PR #{number} checks and Copilot review on {head}");
    Ok(())
}

pub(super) fn verify_repo_readiness(api: &impl Api, args: &Args, repo: &str) -> Result<(), String> {
    let slug = repo
        .strip_prefix("repos/")
        .ok_or_else(|| "invalid repository endpoint".to_string())?;
    let details = api.get(repo)?;
    if !has_string(&details, "full_name", slug) {
        return Err(format!("{repo}: repository identity mismatch"));
    }
    if !has_bool(&details, "archived", false) || !has_bool(&details, "allow_squash_merge", true) {
        return Err(format!(
            "{repo}: enable squash merges on an active repository before applying"
        ));
    }
    if args.is_dotagent() {
        let default = details
            .get("default_branch")
            .and_then(JsonValue::as_str)
            .filter(|branch| !branch.is_empty() && !branch.chars().any(char::is_control))
            .ok_or_else(|| format!("{repo}: missing default branch"))?;
        let repo_id =
            positive_id(&details).ok_or_else(|| format!("{repo}: missing repository ID"))?;
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
        verify_pr_checks(api, repo, repo_id, default, args.proof_pr)?;
    }
    Ok(())
}

fn valid_reviewer(entry: &JsonValue) -> bool {
    let Some(reviewer) = entry
        .get("reviewer")
        .filter(|reviewer| positive_id(reviewer).is_some())
    else {
        return false;
    };
    match entry.get("type").and_then(JsonValue::as_str) {
        Some("User") => reviewer
            .get("login")
            .and_then(JsonValue::as_str)
            .is_some_and(valid_account_login),
        Some("Team") => reviewer
            .get("slug")
            .and_then(JsonValue::as_str)
            .is_some_and(|slug| validate_github_ident(slug).is_ok()),
        _ => false,
    }
}

fn require_no_shared_promoter_secret(
    api: &impl Api,
    repo: &str,
    resource: &str,
) -> Result<(), String> {
    let endpoint = format!("{repo}/actions/{resource}?per_page=100");
    for item in api.items(&endpoint, ".secrets[]")? {
        let name = item
            .get("name")
            .and_then(JsonValue::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("{endpoint}: malformed Actions secret metadata"))?;
        if name.eq_ignore_ascii_case(PROMOTER_SECRET) {
            return Err(format!(
                "{endpoint}: remove shared {PROMOTER_SECRET}; use the protected release environment"
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_release_settings(
    api: &impl Api,
    repo: &str,
    app_id: u64,
) -> Result<(), String> {
    let environment = format!("{repo}/environments/release");
    let env = api.get(&environment)?;
    let reviewers_configured = has_string(&env, "name", "release")
        && env
            .get("protection_rules")
            .and_then(JsonValue::as_array)
            .is_some_and(|rules| {
                rules.iter().any(|rule| {
                    has_string(rule, "type", "required_reviewers")
                        && rule
                            .get("reviewers")
                            .and_then(JsonValue::as_array)
                            .is_some_and(|reviewers| {
                                !reviewers.is_empty() && reviewers.iter().all(valid_reviewer)
                            })
                })
            });
    if !reviewers_configured {
        return Err("release environment requires at least one configured reviewer".to_string());
    }
    let bypass_unverified = match env.get("can_admins_bypass") {
        Some(JsonValue::Bool(false)) => false,
        None => true,
        _ => return Err("release environment must disable administrator bypass".to_string()),
    };
    let variable = api.get(&format!("{environment}/variables/{PROMOTER_VARIABLE}"))?;
    if !has_string(&variable, "name", PROMOTER_VARIABLE)
        || !has_string(&variable, "value", &app_id.to_string())
    {
        return Err(format!(
            "release environment {PROMOTER_VARIABLE} does not match --promoter-app-id"
        ));
    }
    let metadata = api.get(&format!("{environment}/secrets/{PROMOTER_SECRET}"))?;
    if !has_string(&metadata, "name", PROMOTER_SECRET) {
        return Err(format!(
            "missing release environment {PROMOTER_SECRET} metadata"
        ));
    }
    let slug = repo
        .strip_prefix("repos/")
        .ok_or_else(|| "invalid repository endpoint".to_string())?;
    let details = api.get(repo)?;
    if !has_string(&details, "full_name", slug) {
        return Err(format!("{repo}: repository identity mismatch"));
    }
    let owner_type = details
        .get("owner")
        .and_then(|owner| owner.get("type"))
        .and_then(JsonValue::as_str);
    require_no_shared_promoter_secret(api, repo, "secrets")?;
    match owner_type {
        Some("Organization") => {
            require_no_shared_promoter_secret(api, repo, "organization-secrets")?
        }
        Some("User") => {}
        _ => return Err(format!("{repo}: missing repository owner type")),
    }
    if bypass_unverified {
        eprintln!(
            "GitHub's environment API did not report administrator bypass. Verify it is disabled in the release environment settings."
        );
    }
    eprintln!(
        "GitHub's secret metadata cannot verify the promoter App private key or its installation permissions."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const REPO: &str = "repos/susanbdev/dotagent";
    const REPO_ID: u64 = 19;
    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
    const BASE: &str = "0123456789abcdef0123456789abcdef01234568";
    const REPO_DETAILS: &str = r#"{"id":19,"full_name":"susanbdev/dotagent","default_branch":"main","archived":false,"allow_squash_merge":true,"permissions":{"admin":true},"owner":{"type":"User"}}"#;

    #[derive(Default)]
    struct FixtureApi {
        responses: BTreeMap<String, Result<JsonValue, String>>,
        after_first: BTreeMap<String, JsonValue>,
        reads: RefCell<BTreeMap<String, usize>>,
    }

    impl FixtureApi {
        fn respond(&mut self, endpoint: &str, raw: &str) {
            self.set(&format!("{REPO}/{endpoint}"), raw);
        }

        fn set(&mut self, endpoint: &str, raw: &str) {
            self.responses.insert(
                endpoint.to_string(),
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

        fn copilot_review(&mut self, state: &str) {
            self.respond(
                "pulls/6/reviews?per_page=100",
                &format!(r#"[{{"id":17,"state":"{state}","commit_id":"{HEAD}","submitted_at":"2026-11-02T10:00:00Z","user":{{"login":"copilot-pull-request-reviewer[bot]","id":{COPILOT_REVIEWER_ID},"type":"Bot"}}}}]"#),
            );
            self.respond("pulls/6/reviews/17/comments?per_page=100", "[]");
        }
    }

    impl Api for FixtureApi {
        fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
            if let Some(current) = self.after_first.get(endpoint) {
                let mut reads = self.reads.borrow_mut();
                let count = reads.entry(endpoint.to_string()).or_default();
                *count += 1;
                if *count > 1 {
                    return Ok(current.clone());
                }
            }
            self.responses
                .get(endpoint)
                .unwrap_or_else(|| panic!("unexpected fixture request: {endpoint}"))
                .clone()
        }

        fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String> {
            let expected = if endpoint.contains("/check-runs?") {
                ".check_runs[]"
            } else if endpoint.contains("-secrets?") || endpoint.contains("/secrets?") {
                ".secrets[]"
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

    fn check(name: &str, id: u64, app: u64, conclusion: &str, head: &str) -> JsonValue {
        JsonValue::Object(vec![
            ("name".to_string(), JsonValue::Str(name.to_string())),
            ("id".to_string(), JsonValue::Uint(id)),
            ("head_sha".to_string(), JsonValue::Str(head.to_string())),
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

    fn pr_details(head: &str) -> String {
        format!(
            r#"{{"number":6,"state":"closed","merged":true,"draft":false,"head":{{"sha":"{head}"}},"base":{{"ref":"main","sha":"{BASE}","repo":{{"id":{REPO_ID},"full_name":"susanbdev/dotagent"}}}}}}"#
        )
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
        api.respond("pulls/6", &pr_details(HEAD));
        api.set(REPO, REPO_DETAILS);

        let mut checks: Vec<_> = dotagent_required_checks()
            .filter(|&name| name != COPILOT_GATE_CONTEXT)
            .map(|name| check(name, 1, GITHUB_ACTIONS_INTEGRATION_ID, "success", HEAD))
            .collect();
        let required = dotagent_required_checks().next().expect("CI check");
        checks.push(check(
            required,
            3,
            GITHUB_ACTIONS_INTEGRATION_ID,
            "failure",
            HEAD,
        ));
        checks.push(check(
            required,
            4,
            GITHUB_ACTIONS_INTEGRATION_ID + 1,
            "success",
            HEAD,
        ));
        let gate = |id| {
            format!(
                r#"{{"context":"Ring-0 & Copilot Gate","state":"success","creator":{{"login":"github-actions[bot]","id":{id},"type":"Bot"}}}}"#
            )
        };
        let green_gate = format!("[{}]", gate(GITHUB_ACTIONS_BOT_ID));
        api.check_fixture(checks.clone(), &green_gate);
        let failure = verify_pr_checks(&api, REPO, REPO_ID, "main", None)
            .expect_err("newest trusted failure wins");
        assert!(failure.contains("PR #6") && failure.contains(HEAD) && failure.contains(required));

        checks.push(check(
            required,
            5,
            GITHUB_ACTIONS_INTEGRATION_ID,
            "success",
            BASE,
        ));
        api.check_fixture(checks.clone(), &green_gate);
        assert!(
            verify_pr_checks(&api, REPO, REPO_ID, "main", Some(6))
                .expect_err("latest green evidence must identify exact head")
                .ends_with(required)
        );

        checks.push(check(
            required,
            6,
            GITHUB_ACTIONS_INTEGRATION_ID,
            "success",
            HEAD,
        ));
        let other_provider = format!("[{},{}]", gate(78), gate(GITHUB_ACTIONS_BOT_ID));
        api.check_fixture(checks.clone(), &other_provider);
        let failure = verify_pr_checks(&api, REPO, REPO_ID, "main", Some(6))
            .expect_err("latest status creator matters");
        assert!(failure.ends_with(COPILOT_GATE_CONTEXT));

        api.check_fixture(checks, &green_gate);
        api.copilot_review("DISMISSED");
        assert!(
            verify_pr_checks(&api, REPO, REPO_ID, "main", None)
                .expect_err("dismissal requires a new clean review")
                .contains("Copilot review")
        );

        api.copilot_review("COMMENTED");
        api.respond("pulls/6/reviews/17/comments?per_page=100", r#"[{"id":91}]"#);
        assert!(
            verify_pr_checks(&api, REPO, REPO_ID, "main", None)
                .expect_err("direct review evidence shows inline findings")
                .contains("inline findings")
        );

        api.copilot_review("COMMENTED");
        verify_pr_checks(&api, REPO, REPO_ID, "main", None)
            .expect("all exact-head evidence is green");

        api.after_first.insert(
            format!("{REPO}/pulls/6"),
            JsonValue::parse(&pr_details(BASE)).unwrap(),
        );
        assert!(
            verify_pr_checks(&api, REPO, REPO_ID, "main", None)
                .expect_err("proof head moved during evidence collection")
                .contains("changed during")
        );
    }

    #[test]
    fn release_requires_environment_key_and_rejects_shared_duplicates() {
        let mut api = FixtureApi::default();
        api.respond(
            "environments/release",
            r#"{"name":"release","can_admins_bypass":false,"protection_rules":[{"type":"required_reviewers","reviewers":[{"type":"User","reviewer":{"id":42,"login":"trusted-reviewer"}}]}]}"#,
        );
        api.respond(
            "environments/release/variables/PROMOTER_APP_ID",
            r#"{"name":"PROMOTER_APP_ID","value":"42"}"#,
        );
        let environment_key = format!("{REPO}/environments/release/secrets/{PROMOTER_SECRET}");
        api.responses.insert(
            environment_key.clone(),
            Err(format!("GET {environment_key}: HTTP 404")),
        );
        assert!(
            verify_release_settings(&api, REPO, 42)
                .expect_err("environment key cannot use a shared fallback")
                .ends_with("HTTP 404")
        );

        api.respond(
            "environments/release/secrets/PROMOTER_APP_PRIVATE_KEY",
            r#"{"name":"PROMOTER_APP_PRIVATE_KEY"}"#,
        );
        api.set(REPO, REPO_DETAILS);
        api.respond(
            "actions/secrets?per_page=100",
            r#"[{"name":"PROMOTER_APP_PRIVATE_KEY"}]"#,
        );
        assert!(
            verify_release_settings(&api, REPO, 42)
                .expect_err("repository duplicate bypasses protected environment")
                .contains("remove shared")
        );

        api.respond("actions/secrets?per_page=100", "[]");
        verify_release_settings(&api, REPO, 42).expect("environment key is exclusive");

        api.set(
            REPO,
            &REPO_DETAILS.replace(r#""User""#, r#""Organization""#),
        );
        api.respond(
            "actions/organization-secrets?per_page=100",
            r#"[{"name":"PROMOTER_APP_PRIVATE_KEY"}]"#,
        );
        assert!(
            verify_release_settings(&api, REPO, 42)
                .expect_err("reachable organization duplicate bypasses protected environment")
                .contains("remove shared")
        );
    }

    #[test]
    fn apply_requires_real_account_exact_admin_and_disabled_actions_approval() {
        let mut api = FixtureApi::default();
        api.set("user", r#"{"login":"alice","id":42,"type":"User"}"#);
        api.set(REPO, REPO_DETAILS);
        let repo_scope = Scope::Repo("susanbdev/dotagent".into());
        let permission = "actions/permissions/workflow";
        api.respond(permission, r#"{"can_approve_pull_request_reviews":true}"#);
        assert!(
            verify_apply_authority(&api, &repo_scope)
                .expect_err("Actions must not approve reviews")
                .contains("approval disabled")
        );
        api.respond(permission, r#"{"can_approve_pull_request_reviews":false}"#);
        assert_eq!(
            verify_apply_authority(&api, &repo_scope),
            Ok(("alice".into(), 42, REPO_ID))
        );

        api.set(
            REPO,
            &REPO_DETAILS.replace("susanbdev/dotagent", "owner/other"),
        );
        assert!(
            verify_apply_authority(&api, &repo_scope)
                .expect_err("redirected scope needs a fresh command")
                .contains("exact repository admin")
        );

        let org_scope = Scope::Org("test-org".into());
        let membership = "orgs/test-org/memberships/alice";
        let admin = r#"{"state":"active","role":"admin","organization":{"login":"test-org","id":93},"user":{"login":"alice","id":42}}"#;
        api.set(membership, &admin.replace("42", "43"));
        assert!(
            verify_apply_authority(&api, &org_scope)
                .expect_err("membership user must match authenticated user")
                .contains("organization admin")
        );
        api.set(membership, admin);
        api.set(
            "orgs/test-org/actions/permissions/workflow",
            r#"{"can_approve_pull_request_reviews":false}"#,
        );
        assert_eq!(
            verify_apply_authority(&api, &org_scope),
            Ok(("alice".into(), 42, 93))
        );

        api.set("user", r#"{"login":"alice","id":42,"type":"Bot"}"#);
        assert!(
            verify_apply_authority(&api, &org_scope)
                .expect_err("bot authentication cannot administer rulesets")
                .contains("user account")
        );
    }

    #[test]
    fn http_status_comes_from_headers_only() {
        assert_eq!(
            split_http_response(
                "HTTP/2.0 403 Forbidden\nContent-Type: application/json\r\n\r\n{\"message\":\"HTTP 404\"}"
            ),
            Some((403, r#"{"message":"HTTP 404"}"#))
        );
        assert!(split_http_response("gh: HTTP 404\n\n").is_none());
        let api = GhApi {
            gh: PathBuf::from("/a-nonexistent-test-binary"),
        };
        assert_eq!(
            api.write("POST", "user", &JsonValue::Null),
            Err("POST: invalid GitHub ruleset endpoint".into())
        );
    }
}

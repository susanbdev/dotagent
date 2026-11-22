#![forbid(unsafe_code)]

//! Scoped reconciliation of Dotagent-managed GitHub rulesets.

mod api;
mod policy;

use std::io::{self, IsTerminal, Read, Write};
use std::process::ExitCode;

use crate::feedback_loop::validate_owner_repo;
use crate::github_governance::validate_github_ident;
use crate::json::JsonValue;

use self::api::{
    Api, GhApi, encode_url_component, verify_apply_authority, verify_release_settings,
    verify_repo_readiness,
};

const USAGE: &str = "Usage: dotagent github-rulesets (--repo OWNER/REPO | --org ORG)\n\
    [--include-repo NAME]... [--dry-run | --verify | --apply]\n\
    [--proof-pr NUMBER] [--promoter-app-id ID]\n\
    --dry-run     Print the desired rulesets offline (default)\n\
    --verify      Check GitHub for drift without writing\n\
    --apply       Reconcile managed rulesets from a verified administrator's terminal";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    Repo(String),
    Org(String),
}

impl Scope {
    fn owner_path(&self) -> String {
        match self {
            Self::Repo(repo) => format!("repos/{repo}"),
            Self::Org(org) => format!("orgs/{org}"),
        }
    }

    fn source(&self) -> (&str, &str) {
        match self {
            Self::Repo(repo) => ("Repository", repo),
            Self::Org(org) => ("Organization", org),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plan,
    Verify,
    Apply,
}

#[derive(Debug)]
struct Args {
    scope: Scope,
    include_repos: Vec<String>,
    mode: Mode,
    proof_pr: Option<u64>,
    promoter_app_id: Option<u64>,
}

impl Args {
    fn is_dotagent(&self) -> bool {
        match &self.scope {
            Scope::Repo(repo) => repo
                .split_once('/')
                .is_some_and(|(_, name)| name.eq_ignore_ascii_case("dotagent")),
            Scope::Org(_) => false,
        }
    }

    fn parse(raw: &[String]) -> Result<Self, String> {
        let mut arguments = raw.iter().map(String::as_str);
        let mut scope = None;
        let mut mode = None;
        let mut include_repos = Vec::new();
        let mut proof_pr = None;
        let mut promoter_app_id = None;

        while let Some(flag) = arguments.next() {
            match flag {
                "--repo" | "--org" => {
                    if scope.is_some() {
                        return Err("choose one --repo or --org scope".to_string());
                    }
                    let value = flag_value(&mut arguments, flag)?;
                    scope = Some(if flag == "--repo" {
                        let (owner, repository) = validate_owner_repo(value)?;
                        Scope::Repo(format!("{owner}/{repository}"))
                    } else {
                        validate_github_ident(value)?;
                        Scope::Org(value.to_string())
                    });
                }
                "--dry-run" | "--verify" | "--apply" => {
                    if mode.is_some() {
                        return Err("choose at most one mode".to_string());
                    }
                    mode = Some(match flag {
                        "--verify" => Mode::Verify,
                        "--apply" => Mode::Apply,
                        _ => Mode::Plan,
                    });
                }
                "--include-repo" => {
                    let name = flag_value(&mut arguments, flag)?;
                    validate_github_ident(name)?;
                    if name.eq_ignore_ascii_case("dotagent") {
                        return Err(
                            "configure Dotagent separately with --repo OWNER/dotagent".to_string()
                        );
                    }
                    include_repos.push(name.to_string());
                }
                "--proof-pr" | "--promoter-app-id" => {
                    let number = flag_value(&mut arguments, flag)?;
                    let value = number
                        .parse::<u64>()
                        .ok()
                        .filter(|number| *number > 0)
                        .ok_or_else(|| format!("{flag} requires a positive numeric ID"))?;
                    let target = if flag == "--proof-pr" {
                        &mut proof_pr
                    } else {
                        &mut promoter_app_id
                    };
                    if target.replace(value).is_some() {
                        return Err(format!("{flag} can be provided only once"));
                    }
                }
                _ => return Err(format!("unrecognized argument {flag:?}")),
            }
        }

        let args = Self {
            scope: scope.ok_or_else(|| "choose --repo or --org".to_string())?,
            include_repos,
            mode: mode.unwrap_or(Mode::Plan),
            proof_pr,
            promoter_app_id,
        };
        if !args.include_repos.is_empty() && !matches!(args.scope, Scope::Org(_)) {
            return Err("--include-repo requires --org".to_string());
        }
        if (args.proof_pr.is_some() || args.promoter_app_id.is_some()) && !args.is_dotagent() {
            return Err(
                "--proof-pr and --promoter-app-id require a repository named dotagent".to_string(),
            );
        }
        Ok(args)
    }
}

fn flag_value<'a>(args: &mut impl Iterator<Item = &'a str>, flag: &str) -> Result<&'a str, String> {
    args.next()
        .filter(|value| !value.starts_with('-'))
        .ok_or_else(|| format!("{flag} requires a value"))
}

pub(crate) fn run_cli(raw: &[String]) -> ExitCode {
    if matches!(raw, [arg] if matches!(arg.as_str(), "--help" | "-h")) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let result = (|| {
        let args = Args::parse(raw)?;
        let desired = policy::desired(&args)?;
        if args.mode == Mode::Plan {
            let plan = JsonValue::Object(vec![
                (
                    "endpoint".to_string(),
                    JsonValue::Str(format!("{}/rulesets", args.scope.owner_path())),
                ),
                ("rulesets".to_string(), JsonValue::Array(desired)),
            ]);
            println!("{}", plan.to_json_string());
            return Ok(ExitCode::SUCCESS);
        }
        if args.mode == Mode::Apply {
            crate::fleet::verify_operator_not_in_agent_sandbox("dotagent github-rulesets --apply")?;
            if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
                return Err("--apply requires an interactive operator terminal".to_string());
            }
        }
        reconcile(&GhApi::new()?, &args, &desired, confirm_apply)
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("[dotagent github-rulesets] {error}");
            ExitCode::from(2)
        }
    }
}

fn confirm_apply(login: &str, scope: &Scope) -> Result<(), String> {
    let (kind, name) = scope.source();
    let phrase = format!("apply {login} {}", scope.owner_path());
    let mut terminal = io::stderr().lock();
    writeln!(
        terminal,
        "GitHub administrator {login} is applying rules to {kind} {name}."
    )
    .and_then(|()| write!(terminal, "Type '{phrase}' to proceed: "))
    .and_then(|()| terminal.flush())
    .map_err(|error| format!("cannot prompt for operator confirmation: {error}"))?;
    let mut response = String::new();
    use io::BufRead as _;
    io::stdin()
        .lock()
        .take(512)
        .read_line(&mut response)
        .map_err(|error| format!("cannot read operator confirmation: {error}"))?;
    if response.trim_end_matches(['\r', '\n']) != phrase {
        return Err("operator confirmation did not match the administrator and scope".to_string());
    }
    Ok(())
}

fn check_identity(document: &JsonValue, scope: &Scope, name: &str) -> Result<u64, String> {
    let (source_type, source) = scope.source();
    if document.get("name").and_then(JsonValue::as_str) != Some(name)
        || document.get("source_type").and_then(JsonValue::as_str) != Some(source_type)
        || !document
            .get("source")
            .and_then(JsonValue::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(source))
    {
        return Err(format!(
            "{name}: ruleset is outside the selected scope or its identity changed"
        ));
    }
    ruleset_id(document)
}

fn ruleset_id(document: &JsonValue) -> Result<u64, String> {
    document
        .get("id")
        .and_then(JsonValue::as_u64)
        .filter(|id| *id > 0)
        .ok_or_else(|| "GitHub ruleset response lacks a valid ID".to_string())
}

struct Change<'a> {
    name: &'a str,
    desired: &'a JsonValue,
    previous: Option<(u64, JsonValue)>,
}

fn read_managed(
    api: &impl Api,
    listed: &[JsonValue],
    endpoint: &str,
    detail_query: &str,
    scope: &Scope,
    name: &str,
) -> Result<Option<(u64, JsonValue)>, String> {
    let mut found = None;
    for item in listed {
        let item_name = item
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "GitHub returned a malformed ruleset list entry".to_string())?;
        if item_name == name && found.replace(item).is_some() {
            return Err(format!("{name}: multiple managed rulesets found"));
        }
    }
    let Some(metadata) = found else {
        return Ok(None);
    };
    let id = check_identity(metadata, scope, name)?;
    let current = api.get(&format!("{endpoint}/{id}{detail_query}"))?;
    if check_identity(&current, scope, name)? != id {
        return Err(format!("{name}: ruleset ID changed during read"));
    }
    Ok(Some((id, current)))
}

fn verify_org_readiness(api: &impl Api, args: &Args, org: &str) -> Result<(), String> {
    let repos = api.items(&format!("orgs/{org}/repos?type=all&per_page=100"), ".[]")?;
    let mut covered = std::collections::BTreeSet::new();
    for repo in &repos {
        let name = repo
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "GitHub organization repository entry lacks a name".to_string())?;
        validate_github_ident(name)?;
        if name.eq_ignore_ascii_case("dotagent")
            || (!args.include_repos.is_empty()
                && !args
                    .include_repos
                    .iter()
                    .any(|selected| selected.eq_ignore_ascii_case(name)))
        {
            continue;
        }
        if repo.get("archived").and_then(JsonValue::as_bool) == Some(true) {
            continue;
        }
        let slug = format!("{org}/{name}");
        if !repo
            .get("full_name")
            .and_then(JsonValue::as_str)
            .is_some_and(|full_name| full_name.eq_ignore_ascii_case(&slug))
        {
            return Err(format!(
                "organization repository identity does not match {slug}"
            ));
        }
        verify_repo_readiness(api, args, &format!("repos/{slug}"))?;
        covered.insert(name.to_ascii_lowercase());
    }
    if covered.is_empty()
        || args
            .include_repos
            .iter()
            .any(|repo| !covered.contains(&repo.to_ascii_lowercase()))
    {
        return Err(
            "organization policy scope could not be verified for the selected active repositories"
                .to_string(),
        );
    }
    Ok(())
}

fn verify_effective_repo_branch(
    api: &impl Api,
    repo: &str,
    id: u64,
    wanted: &JsonValue,
) -> Result<(), String> {
    let details = api.get(&format!("repos/{repo}"))?;
    if !details
        .get("full_name")
        .and_then(JsonValue::as_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(repo))
    {
        return Err(format!("GitHub repository identity does not match {repo}"));
    }
    let default = details
        .get("default_branch")
        .and_then(JsonValue::as_str)
        .filter(|branch| !branch.is_empty())
        .ok_or_else(|| format!("{repo}: missing default branch"))?;
    let branch = encode_url_component(default);
    let effective = api.items(
        &format!("repos/{repo}/rules/branches/{branch}?per_page=100"),
        ".[]",
    )?;
    policy::verify_effective_branch(wanted, &effective, id, repo)
}

fn check_managed_state(
    api: &impl Api,
    args: &Args,
    desired: &[JsonValue],
    endpoint: &str,
    list_endpoint: &str,
    detail_query: &str,
) -> Result<(), String> {
    let listed = api.items(list_endpoint, ".[]")?;
    for wanted in desired {
        let name = wanted
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "managed ruleset is missing its name".to_string())?;
        let (id, current) = read_managed(api, &listed, endpoint, detail_query, &args.scope, name)?
            .ok_or_else(|| format!("{name}: ruleset missing during final verification"))?;
        let fields = policy::drift(&current, wanted)?;
        if !fields.is_empty() {
            return Err(format!(
                "{name}: drift during final verification in {}",
                fields.join(", ")
            ));
        }
        if let Scope::Repo(repo) = &args.scope
            && wanted.get("target").and_then(JsonValue::as_str) == Some("branch")
        {
            verify_effective_repo_branch(api, repo, id, wanted)?;
        }
    }
    Ok(())
}

fn reconcile(
    api: &impl Api,
    args: &Args,
    desired: &[JsonValue],
    confirm: impl FnOnce(&str, &Scope) -> Result<(), String>,
) -> Result<ExitCode, String> {
    let owner = args.scope.owner_path();
    let endpoint = format!("{owner}/rulesets");
    let (list_query, detail_query) = match &args.scope {
        Scope::Repo(_) => (
            "?includes_parents=false&per_page=100",
            "?includes_parents=false",
        ),
        Scope::Org(_) => ("?per_page=100", ""),
    };
    let list_endpoint = format!("{endpoint}{list_query}");
    let authority = if args.mode == Mode::Apply {
        Some(verify_apply_authority(api, &args.scope)?)
    } else {
        None
    };
    let listed = api.items(&list_endpoint, ".[]")?;
    let mut changes = Vec::new();
    for wanted in desired {
        let name = wanted
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "managed ruleset is missing its name".to_string())?;
        let Some((id, current)) =
            read_managed(api, &listed, &endpoint, detail_query, &args.scope, name)?
        else {
            println!("{name}: missing");
            changes.push(Change {
                name,
                desired: wanted,
                previous: None,
            });
            continue;
        };
        let fields = policy::drift(&current, wanted)?;
        if fields.is_empty() {
            println!("{name}: in sync");
        } else {
            println!("{name}: drift in {}", fields.join(", "));
            if args.mode == Mode::Apply {
                policy::apply_safety(&current, wanted)?;
            }
            changes.push(Change {
                name,
                desired: wanted,
                previous: Some((id, current)),
            });
        }
    }

    if let Some((login, ..)) = &authority
        && !changes.is_empty()
    {
        confirm(login, &args.scope)?;
    }
    if args.mode == Mode::Verify {
        if let Some(app_id) = args.promoter_app_id {
            verify_release_settings(api, &owner, app_id)?;
        }
        if args.proof_pr.is_some() {
            verify_repo_readiness(api, args, &owner)?;
        }
        if changes.is_empty() {
            check_managed_state(api, args, desired, &endpoint, &list_endpoint, detail_query)?;
        }
        return Ok(ExitCode::from(u8::from(!changes.is_empty())));
    }
    match &args.scope {
        Scope::Repo(_) => verify_repo_readiness(api, args, &owner)?,
        Scope::Org(org) => verify_org_readiness(api, args, org)?,
    }
    if let Some(app_id) = args.promoter_app_id {
        verify_release_settings(api, &owner, app_id)?;
    }
    let expected = authority.ok_or_else(|| "only apply mode may reconcile rulesets".to_string())?;
    let mut attempted = 0;
    let apply_result = (|| {
        for change in changes {
            let name = change.name;
            if verify_apply_authority(api, &args.scope)? != expected {
                return Err("GitHub administrator changed since operator confirmation".to_string());
            }
            let listed = api.items(&list_endpoint, ".[]")?;
            if name == "dotagent-release-tag-creation" {
                let immutable_name = "dotagent-release-tag-immutability";
                let immutable = desired
                    .iter()
                    .find(|rule| {
                        rule.get("name").and_then(JsonValue::as_str) == Some(immutable_name)
                    })
                    .ok_or_else(|| "release policy lacks immutable tags".to_string())?;
                let (_, live) = read_managed(
                    api,
                    &listed,
                    &endpoint,
                    detail_query,
                    &args.scope,
                    immutable_name,
                )?
                .ok_or_else(|| "release tag immutability ruleset is absent".to_string())?;
                if !policy::drift(&live, immutable)?.is_empty() {
                    return Err(
                        "release tag immutability drifted before creating the promoter exception"
                            .to_string(),
                    );
                }
            }
            let current = read_managed(api, &listed, &endpoint, detail_query, &args.scope, name)?;
            let (written, operation) = if let Some((id, previous)) = change.previous {
                let path = format!("{endpoint}/{id}");
                let Some((current_id, snapshot)) = current else {
                    return Err(format!("{name}: ruleset disappeared during apply"));
                };
                if current_id != id || !policy::drift(&snapshot, &previous)?.is_empty() {
                    return Err(format!(
                        "{name}: ruleset changed during apply; preview it again"
                    ));
                }
                attempted += 1;
                let written = api.write("PUT", &path, change.desired)?;
                if ruleset_id(&written)? != id {
                    return Err(format!(
                        "{name}: GitHub returned a different ruleset ID after update"
                    ));
                }
                (written, "updated")
            } else {
                if current.is_some() {
                    return Err(format!(
                        "{name}: ruleset appeared during apply; preview it again"
                    ));
                }
                attempted += 1;
                (api.write("POST", &endpoint, change.desired)?, "created")
            };
            let id = ruleset_id(&written)?;
            let updated = api.get(&format!("{endpoint}/{id}{detail_query}"))?;
            if check_identity(&updated, &args.scope, name)? != id {
                return Err(format!("{name}: ruleset ID changed after write"));
            }
            let fields = policy::drift(&updated, change.desired)?;
            if !fields.is_empty() {
                return Err(format!(
                    "{name}: GitHub returned drift after write: {}",
                    fields.join(", ")
                ));
            }
            println!("{name}: {operation} (ID {id})");
        }
        check_managed_state(api, args, desired, &endpoint, &list_endpoint, detail_query)
    })();
    if let Err(error) = apply_result {
        if attempted > 0 {
            return Err(format!(
                "{error}. {attempted} ruleset write(s) attempted; verify the managed rulesets before retrying"
            ));
        }
        return Err(error);
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    const REPO: &str = "fixture-org/library";
    const ENDPOINT: &str = "repos/fixture-org/library/rulesets";

    #[derive(Default)]
    struct Fixture {
        ruleset: RefCell<Option<JsonValue>>,
        writes: Cell<usize>,
        reject_authority: Cell<bool>,
        lose_write_response: Cell<bool>,
        hide_effective_rules: Cell<bool>,
        squash_disabled: Cell<bool>,
    }

    impl Api for Fixture {
        fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
            if endpoint == "user" {
                let kind = if self.reject_authority.get() {
                    "Bot"
                } else {
                    "User"
                };
                return JsonValue::parse(&format!(
                    r#"{{"login":"fixture-admin","id":42,"type":"{kind}"}}"#
                ));
            }
            if endpoint == format!("repos/{REPO}") {
                let squash = !self.squash_disabled.get();
                return JsonValue::parse(&format!(
                    r#"{{"id":77,"full_name":"fixture-org/library","allow_squash_merge":{squash},"archived":false,"default_branch":"main","permissions":{{"admin":true}}}}"#
                ));
            }
            if endpoint == "orgs/fixture-org/memberships/fixture-admin" {
                return JsonValue::parse(
                    r#"{"role":"admin","state":"active","organization":{"login":"fixture-org","id":77},"user":{"login":"fixture-admin","id":42}}"#,
                );
            }
            if endpoint == format!("repos/{REPO}/actions/permissions/workflow")
                || endpoint == "orgs/fixture-org/actions/permissions/workflow"
            {
                return JsonValue::parse(r#"{"can_approve_pull_request_reviews":false}"#);
            }
            assert_eq!(endpoint, format!("{ENDPOINT}/1?includes_parents=false"));
            self.ruleset
                .borrow()
                .clone()
                .ok_or_else(|| "ruleset missing".into())
        }

        fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String> {
            if endpoint == "orgs/fixture-org/repos?type=all&per_page=100" {
                return Ok(vec![JsonValue::parse(
                    r#"{"id":77,"name":"library","full_name":"fixture-org/library","archived":false}"#,
                )?]);
            }
            if endpoint == "orgs/fixture-org/rulesets?per_page=100" {
                return Ok(Vec::new());
            }
            if endpoint == format!("repos/{REPO}/rules/branches/main?per_page=100") {
                if self.hide_effective_rules.get() {
                    return Ok(Vec::new());
                }
                let stored = self.ruleset.borrow();
                let rules = stored
                    .as_ref()
                    .and_then(|ruleset| ruleset.get("rules"))
                    .and_then(JsonValue::as_array)
                    .ok_or("ruleset missing")?;
                return rules
                    .iter()
                    .map(|rule| {
                        let mut fields = rule.as_object().ok_or("rule is not an object")?.to_vec();
                        fields.extend([
                            ("ruleset_id".into(), JsonValue::Uint(1)),
                            (
                                "ruleset_source_type".into(),
                                JsonValue::Str("Repository".into()),
                            ),
                            ("ruleset_source".into(), JsonValue::Str(REPO.into())),
                        ]);
                        Ok(JsonValue::Object(fields))
                    })
                    .collect();
            }
            assert_eq!(
                endpoint,
                format!("{ENDPOINT}?includes_parents=false&per_page=100")
            );
            assert_eq!(selector, ".[]");
            Ok(self.ruleset.borrow().iter().cloned().collect())
        }

        fn write(
            &self,
            method: &str,
            endpoint: &str,
            payload: &JsonValue,
        ) -> Result<JsonValue, String> {
            assert!(matches!(method, "POST" | "PUT"));
            assert!(endpoint.starts_with(ENDPOINT));
            self.writes.set(self.writes.get() + 1);
            let mut record = payload
                .as_object()
                .ok_or("ruleset must be an object")?
                .to_vec();
            record.extend([
                ("id".into(), JsonValue::Uint(1)),
                ("source_type".into(), JsonValue::Str("Repository".into())),
                ("source".into(), JsonValue::Str(REPO.into())),
            ]);
            let record = JsonValue::Object(record);
            self.ruleset.replace(Some(record.clone()));
            if self.lose_write_response.replace(false) {
                return Err("simulated response timeout after commit".into());
            }
            Ok(record)
        }
    }

    fn options(raw: &[&str]) -> Result<Args, String> {
        Args::parse(
            &raw.iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
        )
    }

    fn confirmed(api: &impl Api, args: &Args, desired: &[JsonValue]) -> Result<ExitCode, String> {
        reconcile(api, args, desired, |login, scope| {
            assert_eq!(login, "fixture-admin");
            assert_eq!(scope, &args.scope);
            Ok(())
        })
    }

    #[test]
    fn reconciling_checks_drift_and_writes_only_when_required() {
        let fixture = Fixture::default();
        let verify = options(&["--repo", REPO, "--verify"]).expect("verify arguments");
        let apply = options(&["--repo", REPO, "--apply"]).expect("apply arguments");
        let desired = policy::desired(&apply).expect("repository ruleset");
        assert_eq!(
            confirmed(&fixture, &verify, &desired),
            Ok(ExitCode::from(1))
        );
        assert_eq!(fixture.writes.get(), 0);
        assert_eq!(confirmed(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(confirmed(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(fixture.writes.get(), 1);

        if let Some(JsonValue::Object(fields)) = fixture.ruleset.borrow_mut().as_mut() {
            let (_, enforcement) = fields
                .iter_mut()
                .find(|(key, _)| key == "enforcement")
                .expect("enforcement");
            *enforcement = JsonValue::Str("disabled".into());
        }
        assert_eq!(
            confirmed(&fixture, &verify, &desired),
            Ok(ExitCode::from(1))
        );
        assert_eq!(fixture.writes.get(), 1);
        assert_eq!(confirmed(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(fixture.writes.get(), 2);
        assert_eq!(
            confirmed(&fixture, &verify, &desired),
            Ok(ExitCode::SUCCESS)
        );
    }

    #[test]
    fn identity_checks_prevent_writing_to_a_ruleset_owned_by_other_sources() {
        let fixture = Fixture::default();
        let apply = options(&["--repo", REPO, "--apply"]).expect("apply arguments");
        let desired = policy::desired(&apply).expect("repository ruleset");
        fixture.ruleset.replace(Some(
            JsonValue::parse(r#"{"name":"dotagent-baseline-main","id":1,"source":"fixture-org","source_type":"Organization"}"#)
                .expect("inherited ruleset"),
        ));
        assert!(confirmed(&fixture, &apply, &desired).is_err());
        assert_eq!(fixture.writes.get(), 0);
    }

    #[test]
    fn rejects_unauthorized_or_unconfirmed_apply_without_writes() {
        let fixture = Fixture::default();
        let apply = options(&["--repo", REPO, "--apply"]).expect("apply arguments");
        let desired = policy::desired(&apply).expect("repository ruleset");
        fixture.reject_authority.set(true);
        assert!(
            reconcile(&fixture, &apply, &desired, |_, _| panic!(
                "unauthorized prompt"
            ))
            .is_err()
        );
        assert_eq!(fixture.writes.get(), 0);

        fixture.reject_authority.set(false);
        assert!(
            reconcile(&fixture, &apply, &desired, |_, _| Err(
                "confirmation denied".into()
            ))
            .is_err()
        );
        assert_eq!(fixture.writes.get(), 0);
    }

    #[test]
    fn organization_apply_checks_selected_repositories_before_writing() {
        let fixture = Fixture::default();
        fixture.squash_disabled.set(true);
        let apply = options(&[
            "--org",
            "fixture-org",
            "--include-repo",
            "library",
            "--apply",
        ])
        .expect("organization apply arguments");
        let desired = policy::desired(&apply).expect("organization ruleset");
        let error = confirmed(&fixture, &apply, &desired).expect_err("repository is not ready");
        assert!(error.contains("squash"), "{error}");
        assert_eq!(fixture.writes.get(), 0);
    }

    #[test]
    fn an_interrupted_write_is_reported_and_can_be_verified_without_a_duplicate() {
        let fixture = Fixture::default();
        let apply = options(&["--repo", REPO, "--apply"]).expect("apply arguments");
        let verify = options(&["--repo", REPO, "--verify"]).expect("verify arguments");
        let desired = policy::desired(&apply).expect("repository ruleset");
        fixture.lose_write_response.set(true);
        let error = confirmed(&fixture, &apply, &desired).expect_err("write outcome is unknown");
        assert!(error.contains("1 ruleset write(s) attempted"));
        assert_eq!(
            confirmed(&fixture, &verify, &desired),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(confirmed(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(fixture.writes.get(), 1);
        fixture.hide_effective_rules.set(true);
        assert!(confirmed(&fixture, &verify, &desired).is_err());
        assert_eq!(fixture.writes.get(), 1);
    }

    #[test]
    fn missing_dotagent_proof_blocks_missing_or_drifting_tag_rules() {
        struct UnreadyDotagent {
            existing: Vec<JsonValue>,
            writes: Cell<usize>,
        }

        impl Api for UnreadyDotagent {
            fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
                match endpoint {
                    "user" => JsonValue::parse(r#"{"login":"fixture-admin","id":42,"type":"User"}"#),
                    "repos/fixture-org/dotagent" => JsonValue::parse(r#"{"id":77,"full_name":"fixture-org/dotagent","allow_squash_merge":true,"archived":false,"default_branch":"main","permissions":{"admin":true}}"#),
                    "repos/fixture-org/dotagent/actions/permissions/workflow" => JsonValue::parse(r#"{"can_approve_pull_request_reviews":false}"#),
                    "repos/fixture-org/dotagent/pulls/23" => Err("proof PR unavailable".into()),
                    _ => self.existing.iter().find(|rule| {
                        rule.get("id").and_then(JsonValue::as_u64).is_some_and(|id| {
                            endpoint == format!("repos/fixture-org/dotagent/rulesets/{id}?includes_parents=false")
                        })
                    }).cloned().ok_or_else(|| format!("unexpected GET {endpoint}")),
                }
            }

            fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String> {
                assert_eq!(selector, ".[]");
                match endpoint {
                    "repos/fixture-org/dotagent/rulesets?includes_parents=false&per_page=100" => {
                        Ok(self.existing.clone())
                    }
                    "repos/fixture-org/dotagent/rules/branches/main?per_page=100" => Ok(Vec::new()),
                    _ => Err(format!("unexpected list {endpoint}")),
                }
            }

            fn write(&self, _: &str, _: &str, _: &JsonValue) -> Result<JsonValue, String> {
                self.writes.set(self.writes.get() + 1);
                Err("unexpected governance mutation".into())
            }
        }

        let args = options(&[
            "--repo",
            "fixture-org/dotagent",
            "--apply",
            "--proof-pr",
            "23",
            "--promoter-app-id",
            "1234",
        ])
        .expect("configuration arguments");
        let desired = policy::desired(&args).expect("Dotagent policy");
        let owned = |id: u64, rule: &JsonValue, enforcement: &str| {
            let mut entries = rule.as_object().expect("ruleset object").to_vec();
            entries.retain(|(key, _)| key != "enforcement");
            entries.extend([
                ("enforcement".into(), JsonValue::Str(enforcement.into())),
                ("id".into(), JsonValue::Uint(id)),
                ("source_type".into(), JsonValue::Str("Repository".into())),
                (
                    "source".into(),
                    JsonValue::Str("fixture-org/dotagent".into()),
                ),
            ]);
            JsonValue::Object(entries)
        };
        let branch = owned(10, &desired[0], "active");
        let drifting_tag = owned(11, &desired[1], "disabled");
        for existing in [
            vec![branch.clone()],
            vec![branch, drifting_tag.clone()],
            vec![drifting_tag],
        ] {
            let fixture = UnreadyDotagent {
                existing,
                writes: Cell::new(0),
            };
            let error = confirmed(&fixture, &args, &desired).expect_err("reject missing proof");
            assert!(error.contains("proof PR unavailable"), "{error}");
            assert_eq!(fixture.writes.get(), 0);
        }
    }

    #[test]
    fn scope_and_mode_are_unambiguous() {
        assert_eq!(
            options(&["--org", "fixture-org"])
                .expect("org arguments")
                .mode,
            Mode::Plan
        );
        for args in [
            &["--org", "fixture-org", "--repo", REPO][..],
            &["--repo", REPO, "--verify", "--apply"][..],
            &["--repo", REPO, "--promoter-app-id", "1"][..],
            &["--org", "fixture-org", "--include-repo", "Dotagent"][..],
        ] {
            assert!(options(args).is_err(), "{args:?}");
        }
    }
}

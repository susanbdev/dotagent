#![forbid(unsafe_code)]

//! Scoped reconciliation of Dotagent-managed GitHub rulesets.

mod api;
mod policy;

use std::process::ExitCode;

use crate::feedback_loop::validate_owner_repo;
use crate::github_governance::validate_github_ident;
use crate::json::JsonValue;

use self::api::{Api, GhApi, verify_release_settings, verify_repo_readiness};

const USAGE: &str = "Usage: dotagent github-rulesets (--repo OWNER/REPO | --org ORG)\n\
    [--include-repo NAME]... [--dry-run | --verify | --apply]\n\
    [--proof-pr NUMBER] [--promoter-app-id ID]\n\
    --dry-run     Print the desired rulesets offline (default)\n\
    --verify      Check GitHub for drift without writing\n\
    --apply       Reconcile only the managed rulesets";

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
        }
        reconcile(&GhApi::new()?, &args, &desired)
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("[dotagent github-rulesets] {error}");
            ExitCode::from(2)
        }
    }
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

fn reconcile(api: &impl Api, args: &Args, desired: &[JsonValue]) -> Result<ExitCode, String> {
    let owner = args.scope.owner_path();
    let endpoint = format!("{owner}/rulesets");
    let (list_query, detail_query) = match &args.scope {
        Scope::Repo(_) => (
            "?includes_parents=false&per_page=100",
            "?includes_parents=false",
        ),
        Scope::Org(_) => ("?per_page=100", ""),
    };
    let listed = api.items(&format!("{endpoint}{list_query}"), ".[]")?;
    let mut changes = Vec::new();
    for wanted in desired {
        let name = wanted
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "managed ruleset is missing its name".to_string())?;
        let mut matching = listed
            .iter()
            .filter(|item| item.get("name").and_then(JsonValue::as_str) == Some(name));
        let Some(metadata) = matching.next() else {
            println!("{name}: missing");
            changes.push(Change {
                name,
                desired: wanted,
                previous: None,
            });
            continue;
        };
        if matching.next().is_some() {
            return Err(format!("{name}: multiple managed rulesets found"));
        }
        let id = check_identity(metadata, &args.scope, name)?;
        let current = api.get(&format!("{endpoint}/{id}{detail_query}"))?;
        if check_identity(&current, &args.scope, name)? != id {
            return Err(format!("{name}: ruleset ID changed during read"));
        }
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

    if let Some(app_id) = args.promoter_app_id {
        verify_release_settings(api, &owner, app_id)?;
    }
    if args.mode == Mode::Verify {
        if args.proof_pr.is_some() {
            verify_repo_readiness(api, args, &owner)?;
        }
        return Ok(ExitCode::from(u8::from(!changes.is_empty())));
    }
    if args.is_dotagent() || (matches!(args.scope, Scope::Repo(_)) && !changes.is_empty()) {
        verify_repo_readiness(api, args, &owner)?;
    }
    for change in changes {
        let name = change.name;
        let (written, operation) = if let Some((id, previous)) = change.previous {
            let path = format!("{endpoint}/{id}");
            let snapshot = api.get(&format!("{path}{detail_query}"))?;
            if check_identity(&snapshot, &args.scope, name)? != id
                || !policy::drift(&snapshot, &previous)?.is_empty()
            {
                return Err(format!(
                    "{name}: ruleset changed during apply; preview it again"
                ));
            }
            let written = api.write("PUT", &path, change.desired)?;
            if ruleset_id(&written)? != id {
                return Err(format!(
                    "{name}: GitHub returned a different ruleset ID after update"
                ));
            }
            (written, "updated")
        } else {
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
    }

    impl Api for Fixture {
        fn get(&self, endpoint: &str) -> Result<JsonValue, String> {
            if endpoint == format!("repos/{REPO}") {
                return JsonValue::parse(r#"{"allow_squash_merge":true,"archived":false}"#);
            }
            assert_eq!(endpoint, format!("{ENDPOINT}/1?includes_parents=false"));
            self.ruleset
                .borrow()
                .clone()
                .ok_or_else(|| "ruleset missing".into())
        }

        fn items(&self, endpoint: &str, selector: &str) -> Result<Vec<JsonValue>, String> {
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

    #[test]
    fn reconciling_checks_drift_and_writes_only_when_required() {
        let fixture = Fixture::default();
        let verify = options(&["--repo", REPO, "--verify"]).expect("verify arguments");
        let apply = options(&["--repo", REPO, "--apply"]).expect("apply arguments");
        let desired = policy::desired(&apply).expect("repository ruleset");
        assert_eq!(
            reconcile(&fixture, &verify, &desired),
            Ok(ExitCode::from(1))
        );
        assert_eq!(fixture.writes.get(), 0);
        assert_eq!(reconcile(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(reconcile(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(fixture.writes.get(), 1);

        if let Some(JsonValue::Object(fields)) = fixture.ruleset.borrow_mut().as_mut() {
            let (_, enforcement) = fields
                .iter_mut()
                .find(|(key, _)| key == "enforcement")
                .expect("enforcement");
            *enforcement = JsonValue::Str("disabled".into());
        }
        assert_eq!(
            reconcile(&fixture, &verify, &desired),
            Ok(ExitCode::from(1))
        );
        assert_eq!(fixture.writes.get(), 1);
        assert_eq!(reconcile(&fixture, &apply, &desired), Ok(ExitCode::SUCCESS));
        assert_eq!(fixture.writes.get(), 2);
        assert_eq!(
            reconcile(&fixture, &verify, &desired),
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
        assert!(reconcile(&fixture, &apply, &desired).is_err());
        assert_eq!(fixture.writes.get(), 0);
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

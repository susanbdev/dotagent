use std::collections::BTreeSet;

use super::{Args, Scope};
use crate::github_governance::{
    COPILOT_GATE_CONTEXT, RATCHET_CHECK_RUN, build_main_ruleset_payload, dotagent_required_checks,
};
use crate::json::JsonValue;

const POLICY_FIELDS: [&str; 6] = [
    "name",
    "target",
    "enforcement",
    "conditions",
    "bypass_actors",
    "rules",
];

fn object<const N: usize>(fields: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn string(value: &str) -> JsonValue {
    JsonValue::Str(value.to_owned())
}

fn strings<'a>(values: impl IntoIterator<Item = &'a str>) -> JsonValue {
    JsonValue::Array(values.into_iter().map(string).collect())
}

fn check_catalog() -> Result<Vec<String>, String> {
    let mut names = BTreeSet::new();
    let checks: Vec<_> = dotagent_required_checks().collect();
    if checks.iter().any(|name| {
        name.is_empty()
            || name.trim() != *name
            || name.chars().any(char::is_control)
            || !names.insert(*name)
    }) || !names.contains(COPILOT_GATE_CONTEXT)
        || !names.contains(RATCHET_CHECK_RUN)
    {
        return Err("invalid status check catalog github-required-checks.txt".to_owned());
    }
    Ok(checks.into_iter().map(str::to_owned).collect())
}

fn ref_name(include: &str) -> JsonValue {
    object([
        ("include", strings([include])),
        ("exclude", JsonValue::Array(Vec::new())),
    ])
}

fn organization_conditions(include_repos: &[String]) -> JsonValue {
    let names: BTreeSet<_> = include_repos.iter().map(String::as_str).collect();
    let include = if names.is_empty() {
        strings(["~ALL"])
    } else {
        strings(names)
    };
    object([
        ("ref_name", ref_name("~DEFAULT_BRANCH")),
        (
            "repository_name",
            object([
                ("include", include),
                ("exclude", strings(["dotagent"])),
                ("protected", JsonValue::Bool(false)),
            ]),
        ),
    ])
}

fn tag_ruleset(name: &str, types: &[&str], bypass: Vec<JsonValue>) -> JsonValue {
    object([
        ("name", string(name)),
        ("target", string("tag")),
        ("enforcement", string("active")),
        ("bypass_actors", JsonValue::Array(bypass)),
        (
            "conditions",
            object([("ref_name", ref_name("refs/tags/v*"))]),
        ),
        (
            "rules",
            JsonValue::Array(
                types
                    .iter()
                    .map(|rule| object([("type", string(rule))]))
                    .collect(),
            ),
        ),
    ])
}

pub(super) fn desired(args: &Args) -> Result<Vec<JsonValue>, String> {
    let dotagent = args.is_dotagent();
    let checks = if dotagent {
        check_catalog()?
    } else {
        Vec::new()
    };
    let mut branch = build_main_ruleset_payload(&checks, dotagent);
    if !dotagent {
        let JsonValue::Object(fields) = &mut branch else {
            return Err("default-branch ruleset payload is not an object".to_owned());
        };
        for (field, value) in fields {
            match field.as_str() {
                "name" => *value = string("dotagent-baseline-main"),
                "conditions" if matches!(&args.scope, Scope::Org(_)) => {
                    *value = organization_conditions(&args.include_repos);
                }
                _ => {}
            }
        }
    }

    let mut output = vec![branch];
    if let Some(id) = args.promoter_app_id {
        if !dotagent || id == 0 {
            return Err(
                "release promoter requires a positive App ID and an OWNER/dotagent repository"
                    .to_owned(),
            );
        }
        output.push(tag_ruleset(
            "dotagent-release-tag-immutability",
            &["update", "deletion", "non_fast_forward"],
            Vec::new(),
        ));
        output.push(tag_ruleset(
            "dotagent-release-tag-creation",
            &["creation"],
            vec![object([
                ("actor_id", JsonValue::Uint(id)),
                ("actor_type", string("Integration")),
                ("bypass_mode", string("always")),
            ])],
        ));
    }
    Ok(output)
}

fn name(doc: &JsonValue) -> &str {
    doc.get("name")
        .and_then(JsonValue::as_str)
        .unwrap_or("ruleset")
}

fn require_bypass_metadata(doc: &JsonValue) -> Result<(), String> {
    if doc
        .get("bypass_actors")
        .and_then(JsonValue::as_array)
        .is_none()
    {
        return Err(format!(
            "{}: GitHub omitted bypass actors; use ruleset-write access",
            name(doc)
        ));
    }
    Ok(())
}

fn canonical(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .filter_map(|(key, value)| {
                    let default = match (key.as_str(), value) {
                        ("parameters", JsonValue::Object(fields)) => fields.is_empty(),
                        ("required_reviewers", JsonValue::Array(reviewers)) => reviewers.is_empty(),
                        _ => false,
                    };
                    (!default).then(|| (key.clone(), canonical(value)))
                })
                .collect();
            fields.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            JsonValue::Object(fields)
        }
        JsonValue::Array(values) => {
            let mut values: Vec<_> = values.iter().map(canonical).collect();
            values.sort_by_cached_key(JsonValue::to_json_string);
            JsonValue::Array(values)
        }
        _ => value.clone(),
    }
}

fn normalized_field(doc: &JsonValue, field: &str) -> JsonValue {
    let value = doc.get(field).unwrap_or(&JsonValue::Null);
    if field != "conditions" {
        return canonical(value);
    }
    let mut conditions = value.clone();
    if let JsonValue::Object(fields) = &mut conditions {
        for (key, value) in fields {
            if matches!(key.as_str(), "ref_name" | "repository_name")
                && let JsonValue::Object(entries) = value
            {
                if !entries.iter().any(|(name, _)| name == "exclude") {
                    entries.push(("exclude".to_owned(), JsonValue::Array(Vec::new())));
                }
                if key == "repository_name" && !entries.iter().any(|(name, _)| name == "protected")
                {
                    entries.push(("protected".to_owned(), JsonValue::Bool(false)));
                }
            }
        }
    }
    canonical(&conditions)
}

pub(super) fn drift(existing: &JsonValue, wanted: &JsonValue) -> Result<Vec<&'static str>, String> {
    require_bypass_metadata(existing)?;
    require_bypass_metadata(wanted)?;
    Ok(POLICY_FIELDS
        .into_iter()
        .filter(|field| normalized_field(existing, field) != normalized_field(wanted, field))
        .collect())
}

pub(super) fn verify_effective_branch(
    wanted: &JsonValue,
    effective: &[JsonValue],
    id: u64,
    repo: &str,
) -> Result<(), String> {
    let expected = wanted
        .get("rules")
        .filter(|rules| rules.as_array().is_some_and(|rules| !rules.is_empty()))
        .ok_or_else(|| format!("{}: missing desired branch rules", name(wanted)))?;
    let mut owned = Vec::new();
    for rule in effective {
        if rule.get("ruleset_id").and_then(JsonValue::as_u64) != Some(id) {
            continue;
        }
        if rule.get("ruleset_source_type").and_then(JsonValue::as_str) != Some("Repository")
            || !rule
                .get("ruleset_source")
                .and_then(JsonValue::as_str)
                .is_some_and(|source| source.eq_ignore_ascii_case(repo))
        {
            return Err(format!(
                "{}: effective rule source differs from {repo}",
                name(wanted)
            ));
        }
        let fields = rule
            .as_object()
            .ok_or_else(|| format!("{}: malformed effective branch rule", name(wanted)))?;
        owned.push(JsonValue::Object(
            fields
                .iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "ruleset_id" | "ruleset_source_type" | "ruleset_source"
                    )
                })
                .cloned()
                .collect(),
        ));
    }
    if canonical(&JsonValue::Array(owned)) != canonical(expected) {
        return Err(format!(
            "{}: effective default-branch rules for {repo} do not match managed policy",
            name(wanted)
        ));
    }
    Ok(())
}

fn rule_types(doc: &JsonValue) -> Result<BTreeSet<&str>, String> {
    let rules = doc
        .get("rules")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| format!("{}: missing rules array", name(doc)))?;
    let mut types = BTreeSet::new();
    for rule in rules {
        let kind = rule
            .get("type")
            .and_then(JsonValue::as_str)
            .filter(|kind| !kind.is_empty())
            .ok_or_else(|| format!("{}: rule is missing a type", name(doc)))?;
        if !types.insert(kind) {
            return Err(format!(
                "{}: existing ruleset has duplicate '{kind}' rules",
                name(doc)
            ));
        }
    }
    Ok(types)
}

fn parameters<'a>(doc: &'a JsonValue, kind: &str) -> Result<Option<&'a JsonValue>, String> {
    doc.get("rules")
        .and_then(JsonValue::as_array)
        .and_then(|rules| {
            rules
                .iter()
                .find(|rule| rule.get("type").and_then(JsonValue::as_str) == Some(kind))
        })
        .map(|rule| {
            rule.get("parameters")
                .filter(|parameters| parameters.as_object().is_some())
                .ok_or_else(|| format!("{}: '{kind}' has missing or invalid parameters", name(doc)))
        })
        .transpose()
}

fn approval_count(params: &JsonValue) -> Result<u64, String> {
    params
        .get("required_approving_review_count")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| "pull_request rule has missing or invalid approval count".to_owned())
}

fn preserve_review_policy(current: &JsonValue, target: &JsonValue) -> Result<(), String> {
    if approval_count(current)? > approval_count(target)? {
        return Err("apply would reduce the existing approval count".to_owned());
    }
    for field in ["require_code_owner_review", "require_last_push_approval"] {
        let value = current
            .get(field)
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| format!("pull_request rule has missing or invalid {field}"))?;
        if value && target.get(field).and_then(JsonValue::as_bool) != Some(true) {
            return Err(format!("apply would remove existing {field} protection"));
        }
    }
    if let Some(reviewers) = current.get("required_reviewers") {
        let entries = reviewers
            .as_array()
            .ok_or_else(|| "pull_request rule has invalid required_reviewers".to_owned())?;
        if !entries.is_empty()
            && target
                .get("required_reviewers")
                .is_none_or(|replacement| canonical(reviewers) != canonical(replacement))
        {
            return Err("apply would change existing required reviewers".to_owned());
        }
    }
    if let Some(dismissal) = current.get("dismissal_restrictions") {
        let enabled = dismissal
            .get("enabled")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| "pull_request rule has invalid dismissal_restrictions".to_owned())?;
        if enabled
            && target
                .get("dismissal_restrictions")
                .is_none_or(|replacement| canonical(dismissal) != canonical(replacement))
        {
            return Err("apply would change existing review dismissal restrictions".to_owned());
        }
    }
    Ok(())
}

fn status_contexts(params: &JsonValue) -> Result<BTreeSet<&str>, String> {
    let checks = params
        .get("required_status_checks")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "required_status_checks rule has missing or invalid checks".to_owned())?;
    let mut contexts = BTreeSet::new();
    for check in checks {
        let name = check
            .get("context")
            .and_then(JsonValue::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "required_status_checks rule has a missing context".to_owned())?;
        if !contexts.insert(name) {
            return Err(format!(
                "required_status_checks rule has duplicate context '{name}'"
            ));
        }
    }
    Ok(contexts)
}

pub(super) fn apply_safety(existing: &JsonValue, wanted: &JsonValue) -> Result<(), String> {
    require_bypass_metadata(existing)?;
    let target = existing.get("target").and_then(JsonValue::as_str);
    if target.is_none() || target != wanted.get("target").and_then(JsonValue::as_str) {
        return Err(format!(
            "{}: existing ruleset has a different target",
            name(wanted)
        ));
    }
    let known = rule_types(wanted)?;
    let actual = rule_types(existing)?;
    let extra: Vec<_> = actual.difference(&known).copied().collect();
    if !extra.is_empty() {
        return Err(format!(
            "{}: existing ruleset contains unmanaged rules: {}",
            name(wanted),
            extra.join(", ")
        ));
    }
    if let Some(current) = parameters(existing, "pull_request")? {
        let target = parameters(wanted, "pull_request")?
            .ok_or_else(|| "desired ruleset is missing pull_request parameters".to_owned())?;
        preserve_review_policy(current, target)?;
    }
    if let Some(current) = parameters(existing, "required_status_checks")? {
        let target = parameters(wanted, "required_status_checks")?.ok_or_else(|| {
            "desired ruleset is missing required_status_checks parameters".to_owned()
        })?;
        let current = status_contexts(current)?;
        let target = status_contexts(target)?;
        let extra: Vec<_> = current.difference(&target).copied().collect();
        if !extra.is_empty() {
            return Err(format!(
                "{}: apply would remove required status contexts: {}",
                name(wanted),
                extra.join(", ")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_governance::GITHUB_ACTIONS_INTEGRATION_ID;

    fn json(raw: &str) -> JsonValue {
        JsonValue::parse(raw).unwrap()
    }

    fn plan(flags: &[&str]) -> Vec<JsonValue> {
        let flags: Vec<_> = flags.iter().map(|flag| (*flag).to_owned()).collect();
        desired(&Args::parse(&flags).unwrap()).unwrap()
    }

    fn rule<'a>(ruleset: &'a JsonValue, kind: &str) -> &'a JsonValue {
        ruleset
            .get("rules")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule.get("type").and_then(JsonValue::as_str) == Some(kind))
            .unwrap()
    }

    fn approvals(ruleset: &JsonValue) -> Option<u64> {
        rule(ruleset, "pull_request")
            .get("parameters")?
            .get("required_approving_review_count")?
            .as_u64()
    }

    #[test]
    fn baseline_requires_approval_and_org_scope_excludes_dotagent() {
        let repo = plan(&["--repo", "owner/other"]);
        assert_eq!(name(&repo[0]), "dotagent-baseline-main");
        assert_eq!(approvals(&repo[0]), Some(1));
        assert_eq!(repo[0].get("bypass_actors"), Some(&json("[]")));
        assert_eq!(
            rule_types(&repo[0]).unwrap(),
            BTreeSet::from([
                "deletion",
                "non_fast_forward",
                "pull_request",
                "required_linear_history",
            ])
        );
        let org = plan(&[
            "--org",
            "owner",
            "--include-repo",
            "beta",
            "--include-repo",
            "alpha",
            "--include-repo",
            "beta",
        ]);
        assert_eq!(approvals(&org[0]), Some(1));
        assert_eq!(org[0].get("bypass_actors"), Some(&json("[]")));
        let repositories = org[0]
            .get("conditions")
            .unwrap()
            .get("repository_name")
            .unwrap();
        assert_eq!(
            canonical(repositories),
            canonical(&json(
                r#"
            {"include":["alpha","beta"],"exclude":["dotagent"],"protected":false}
        "#
            ))
        );
    }

    #[test]
    fn dotagent_uses_exact_checks_and_separates_tag_creation_from_immutability() {
        let rulesets = plan(&["--repo", "owner/dotagent", "--promoter-app-id", "99"]);
        let [branch, immutable, creation] = rulesets.as_slice() else {
            panic!("expected three rulesets")
        };
        assert_eq!(name(branch), "dotagent-zero-trust-main");
        assert_eq!(approvals(branch), Some(1));
        assert_eq!(branch.get("bypass_actors"), Some(&json("[]")));
        let checks = rule(branch, "required_status_checks")
            .get("parameters")
            .unwrap()
            .get("required_status_checks")
            .unwrap()
            .as_array()
            .unwrap();
        let contexts: Vec<_> = checks
            .iter()
            .map(|check| {
                assert_eq!(
                    check.get("integration_id").and_then(JsonValue::as_u64),
                    Some(GITHUB_ACTIONS_INTEGRATION_ID)
                );
                check.get("context").and_then(JsonValue::as_str).unwrap()
            })
            .collect();
        assert_eq!(contexts, dotagent_required_checks().collect::<Vec<_>>());
        assert_eq!(
            rule_types(immutable).unwrap(),
            BTreeSet::from(["update", "deletion", "non_fast_forward"])
        );
        assert_eq!(immutable.get("bypass_actors"), Some(&json("[]")));
        assert_eq!(rule_types(creation).unwrap(), BTreeSet::from(["creation"]));
        assert_eq!(
            creation.get("bypass_actors"),
            Some(&json(
                r#"
            [{"actor_id":99,"actor_type":"Integration","bypass_mode":"always"}]
        "#
            ))
        );
        for ruleset in [immutable, creation] {
            assert_eq!(
                ruleset.get("target").and_then(JsonValue::as_str),
                Some("tag")
            );
            assert_eq!(
                ruleset.get("conditions").unwrap().get("ref_name"),
                Some(&ref_name("refs/tags/v*"))
            );
        }
    }

    #[test]
    fn drift_normalizes_github_defaults_and_array_order() {
        let wanted = json(
            r#"{
            "name":"managed","target":"branch","enforcement":"active","bypass_actors":[],
            "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]},
            "repository_name":{"include":["alpha","beta"],"exclude":["dotagent"],"protected":false}},
            "rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"required_approving_review_count":1,
            "require_extra_approval_for_unattributed_changes":true}}]
        }"#,
        );
        let response = r#"{
            "id":12,"rules":[{"parameters":{"required_reviewers":[],"required_approving_review_count":1,
            "require_extra_approval_for_unattributed_changes":true},"type":"pull_request"},
            {"parameters":{},"type":"deletion"}],"bypass_actors":[],"enforcement":"active","target":"branch",
            "conditions":{"repository_name":{"exclude":["dotagent"],"include":["beta","alpha"]},
            "ref_name":{"include":["~DEFAULT_BRANCH"]}},"name":"managed"
        }"#;
        assert!(drift(&json(response), &wanted).unwrap().is_empty());
        for changed in [
            response.replace("true", "false"),
            response.replace(
                ",\n            \"require_extra_approval_for_unattributed_changes\":true",
                "",
            ),
            response.replace(
                "required_approving_review_count\":1",
                "required_approving_review_count\":0",
            ),
        ] {
            assert_eq!(drift(&json(&changed), &wanted).unwrap(), vec!["rules"]);
        }
    }

    #[test]
    fn effective_branch_requires_exact_managed_rules_from_the_selected_repository() {
        let wanted = &plan(&["--repo", "owner/dotagent"])[0];
        let effective: Vec<_> = wanted
            .get("rules")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                let mut fields = rule.as_object().unwrap().to_vec();
                fields.extend([
                    ("ruleset_id".to_owned(), JsonValue::Uint(13)),
                    ("ruleset_source".to_owned(), string("Owner/Dotagent")),
                    ("ruleset_source_type".to_owned(), string("Repository")),
                ]);
                JsonValue::Object(fields)
            })
            .collect();
        assert!(verify_effective_branch(wanted, &effective, 13, "owner/dotagent").is_ok());
        assert!(verify_effective_branch(wanted, &effective, 14, "owner/dotagent").is_err());
        assert!(verify_effective_branch(wanted, &effective, 13, "other/dotagent").is_err());
        assert!(
            verify_effective_branch(
                wanted,
                &effective[..effective.len() - 1],
                13,
                "owner/dotagent"
            )
            .is_err()
        );
        let unpinned: Vec<_> = effective
            .iter()
            .map(|rule| {
                json(
                    &rule
                        .to_json_string()
                        .replace("\"integration_id\":15368", "\"integration_id\":1"),
                )
            })
            .collect();
        assert!(verify_effective_branch(wanted, &unpinned, 13, "owner/dotagent").is_err());
    }

    #[test]
    fn omitted_bypass_actors_and_unmanaged_rules_are_rejected() {
        let wanted =
            json(r#"{"target":"branch","bypass_actors":[],"rules":[{"type":"deletion"}]}"#);
        let omitted = json(r#"{"target":"branch","rules":[{"type":"deletion"}]}"#);
        assert!(
            drift(&omitted, &wanted)
                .unwrap_err()
                .contains("omitted bypass actors")
        );
        assert!(apply_safety(&omitted, &wanted).is_err());
        let extra =
            json(r#"{"target":"branch","bypass_actors":[],"rules":[{"type":"merge_queue"}]}"#);
        assert!(
            apply_safety(&extra, &wanted)
                .unwrap_err()
                .contains("unmanaged rules: merge_queue")
        );
        let duplicate = json(
            r#"{"target":"branch","bypass_actors":[],"rules":[{"type":"deletion"},{"type":"deletion"}]}"#,
        );
        assert!(
            apply_safety(&duplicate, &wanted)
                .unwrap_err()
                .contains("duplicate 'deletion' rules")
        );
        assert!(apply_safety(&wanted, &wanted).is_ok());
    }

    #[test]
    fn application_preserves_existing_stronger_review_and_check_requirements() {
        let wanted = &plan(&["--repo", "owner/dotagent"])[0];
        let raw = wanted.to_json_string();
        for (current, replacement, diagnostic) in [
            (
                "\"required_approving_review_count\":1",
                "\"required_approving_review_count\":2",
                "reduce the existing approval count",
            ),
            (
                "\"require_code_owner_review\":false",
                "\"require_code_owner_review\":true",
                "require_code_owner_review",
            ),
            (
                "\"require_last_push_approval\":false",
                "\"require_last_push_approval\":true",
                "require_last_push_approval",
            ),
            (
                "\"require_last_push_approval\":false",
                r#""require_last_push_approval":false,"required_reviewers":[{"reviewer":{"id":1,"type":"Team"},"file_patterns":["**/*"],"minimum_approvals":1}]"#,
                "existing required reviewers",
            ),
            (
                "\"require_last_push_approval\":false",
                r#""require_last_push_approval":false,"dismissal_restrictions":{"enabled":true,"allowed_actors":[]}"#,
                "review dismissal restrictions",
            ),
            (
                "\"required_status_checks\":[",
                r#""required_status_checks":[{"context":"Additional trusted check","integration_id":15368},"#,
                "Additional trusted check",
            ),
        ] {
            let existing = json(&raw.replace(current, replacement));
            assert!(
                apply_safety(&existing, wanted)
                    .unwrap_err()
                    .contains(diagnostic)
            );
        }
        let previous = json(&raw.replace(
            "\"required_approving_review_count\":1",
            "\"required_approving_review_count\":0",
        ));
        assert!(apply_safety(&previous, wanted).is_ok());
    }
}

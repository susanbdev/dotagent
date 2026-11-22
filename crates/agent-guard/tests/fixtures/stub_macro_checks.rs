use super::{
    mask_rust_test_items, rust_cfg_test_item_ranges, rust_source_tokens, rust_stub_macro_lines,
};
use std::collections::BTreeSet;

#[test]
fn recognizes_invocations_and_preserves_source_lines() {
    let source = r##"
            const HELP: &str = "Use todo!() during development.";
            /* Guide: compile out unimplemented!() before release. */
            const RAW: &str = r#"Both todo!() and unimplemented!() require review."#;
            fn draft() { todo ! ("pending implementation"); }
        "##;
    assert_eq!(
        rust_stub_macro_lines(&rust_source_tokens(source), &[]),
        BTreeSet::from([5]),
    );
}

#[test]
fn scans_production_items_on_both_sides_of_test_items() {
    let source = "\
fn before() { todo!(); }\n\
#[cfg(test)]\n\
#[allow(dead_code)]\n\
mod tests {\n\
    fn test_helper() { todo!(); }\n\
}\n\
#[cfg(test)] fn test_only() { todo!(); } fn after() { todo!(); }\n\
#[cfg(test)] mod other_tests;\n\
#[cfg(test)] fixtures::register! { todo!(); }\n\
fn last() { todo!(); }\n";
    let tokens = rust_source_tokens(source);
    let ranges = rust_cfg_test_item_ranges(&tokens);
    assert_eq!(ranges.len(), 4);
    assert_eq!(
        rust_stub_macro_lines(&tokens, &ranges),
        BTreeSet::from([1, 7, 10])
    );
    let masked = mask_rust_test_items(source, &ranges);
    assert_eq!(masked.lines().count(), source.lines().count());
    assert!(
        masked
            .lines()
            .nth(6)
            .is_some_and(|line| line.trim_start() == "fn after() { todo!(); }")
    );
}

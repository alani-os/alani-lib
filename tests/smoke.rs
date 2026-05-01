#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_lib::repository_name(), "alani-lib");
    assert!(!alani_lib::module_names().is_empty());
}

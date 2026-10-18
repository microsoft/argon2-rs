use std::fs;
use std::path::Path;

#[test]
fn verified_sources_do_not_disable_termination() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for directory in ["src", "specs", "proofs"] {
        for entry in fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).unwrap();
                assert!(
                    !source.contains("exec_allows_no_decreases_clause"),
                    "termination opt-out in {}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn canonical_specs_do_not_import_proof_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("specs");
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).unwrap();
            for dependency in [
                "crate::invariant_specs",
                "crate::proofs",
                "crate::blake2b_update_model",
                "crate::blake2b_long_model",
                "crate::initial_hash_model",
                "crate::memory_initialization_model",
            ] {
                assert!(!source.contains(dependency), "{} imports {dependency}", path.display());
            }
        }
    }
}

//! Static contracts for the standalone CLI release transaction.

use serde_yaml::Value;

const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");

fn workflow() -> Value {
    serde_yaml::from_str(RELEASE_WORKFLOW).expect("release workflow must be valid YAML")
}

fn jobs(document: &Value) -> &serde_yaml::Mapping {
    document["jobs"]
        .as_mapping()
        .expect("release workflow must define jobs")
}

fn job<'a>(jobs: &'a serde_yaml::Mapping, name: &str) -> &'a Value {
    jobs.get(Value::String(name.to_owned()))
        .unwrap_or_else(|| panic!("release workflow must define {name}"))
}

fn run_steps(job: &Value) -> String {
    job["steps"]
        .as_sequence()
        .expect("release job must define steps")
        .iter()
        .filter_map(|step| step["run"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn standalone_release_closes_registry_draft_and_latest_in_order() {
    let document = workflow();
    let jobs = jobs(&document);
    let registry = job(jobs, "registry-satisfied");
    let release = job(jobs, "release");
    let draft = job(jobs, "verify-draft");
    let finalize = job(jobs, "finalize");

    assert_eq!(
        registry["needs"],
        serde_yaml::from_str::<Value>("[metadata, build, publish]").unwrap()
    );
    assert!(run_steps(registry).contains(".yanked == false"));
    assert_eq!(
        release["needs"],
        serde_yaml::from_str::<Value>("[metadata, build, registry-satisfied]").unwrap()
    );
    assert!(run_steps(release).contains("--draft"));
    assert!(run_steps(release).contains("exactly six target archives"));
    assert_eq!(
        draft["needs"],
        serde_yaml::from_str::<Value>("[metadata, release]").unwrap()
    );
    assert!(run_steps(draft).contains("sha256sum --check SHA256SUMS"));
    assert!(run_steps(draft).contains("gh attestation verify"));
    assert_eq!(
        finalize["needs"],
        serde_yaml::from_str::<Value>("[metadata, verify-draft]").unwrap()
    );
    assert!(run_steps(finalize).contains("--draft=false --latest"));
    assert!(run_steps(finalize).contains("/releases/latest"));
}

#[test]
fn every_declared_target_has_one_archive_in_both_release_gates() {
    let document = workflow();
    let jobs = jobs(&document);
    let build = run_steps(job(jobs, "build"));
    let release = run_steps(job(jobs, "release"));
    let draft = run_steps(job(jobs, "verify-draft"));
    let targets = [
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ];

    for target in targets {
        assert_eq!(release.matches(target).count(), 1, "release gate: {target}");
        assert_eq!(draft.matches(target).count(), 1, "draft gate: {target}");
    }
    assert!(build.contains("7z a \"dist/${name}.zip\" \"./dist/${name}\""));
    assert!(!build.contains("${name}/*"));
}

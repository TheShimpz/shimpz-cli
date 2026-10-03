//! Proves through a real Python subprocess that a project's excluded `shimpz/` root never shadows the SDK bridge.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SUMMARY: &str = "Verify local file-backed Action execution.";

fn copy_fixture(project: &Path) {
    let fixture = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/assistant"
    ));
    fs::create_dir_all(project.join("actions")).unwrap();
    for name in ["pyproject.toml", "shimpz.toml", "icon.png"] {
        fs::copy(fixture.join(name), project.join(name)).unwrap();
    }
    for name in ["greet.py", "report.py"] {
        fs::copy(
            fixture.join("actions").join(name),
            project.join("actions").join(name),
        )
        .unwrap();
    }
}

/// A real virtual environment whose only `shimpz` package is a trusted stand-in for the pinned SDK bridge.
fn trusted_environment(root: &Path) -> PathBuf {
    let environment = root.join("venv");
    let created = Command::new("python3")
        .args(["-m", "venv", "--without-pip"])
        .arg(&environment)
        .status()
        .expect("python3 is required for this test");
    assert!(created.success());
    let python = environment.join("bin/python");
    let purelib = Command::new(&python)
        .args([
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ])
        .output()
        .unwrap();
    let package = PathBuf::from(String::from_utf8(purelib.stdout).unwrap().trim()).join("shimpz");
    fs::create_dir_all(&package).unwrap();
    fs::write(package.join("__init__.py"), "").unwrap();
    let id = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(SUMMARY));
    fs::write(
        package.join("_bridge.py"),
        format!(
            "import json\nprint(json.dumps({{'messages': [{{'id': '{id}', 'msgid': '{SUMMARY}', 'max_length': 160, 'params': []}}], 'summary': '{SUMMARY}'}}))\n"
        ),
    )
    .unwrap();
    python
}

#[test]
fn an_excluded_shimpz_root_never_runs_in_place_of_the_sdk_bridge() {
    let root = std::env::temp_dir().join(format!("shimpz-bridge-isolation-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let python = trusted_environment(&root);
    let project = root.join("assistant");
    copy_fixture(&project);
    let sentinel = root.join("shadow-executed");
    let shadow = format!(
        "open({:?}, 'w').write('executed')\n",
        sentinel.display().to_string()
    );
    fs::create_dir_all(project.join("shimpz")).unwrap();
    fs::write(project.join("shimpz/__init__.py"), &shadow).unwrap();
    fs::write(project.join("shimpz/_bridge.py"), &shadow).unwrap();
    let uv = root.join("uv");
    fs::write(
        &uv,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'uv 0.11.32'; exit 0; fi\n\
             while [ \"$#\" -gt 0 ] && [ \"$1\" != python ]; do shift; done\n\
             [ \"$#\" -gt 0 ] || exit 1\nshift\nexec '{}' \"$@\"\n",
            python.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o755)).unwrap();

    // Run from inside the project, where a non-isolated `python -m` would import ./shimpz first.
    let output = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .args(["assistant", "stage", "--project", "."])
        .current_dir(&project)
        .env("SHIMPZ_UV", &uv)
        .env("SHIMPZ_CACHE_DIR", root.join("cache"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let executed = sentinel.exists();
    let _ = fs::remove_dir_all(&root);
    assert!(!executed, "the project's shimpz/ package ran: {stderr}");
    // The trusted bridge answered with a valid catalog, so staging reached its prepared-pack requirement.
    assert!(stderr.contains("no language pack is prepared"), "{stderr}");
}

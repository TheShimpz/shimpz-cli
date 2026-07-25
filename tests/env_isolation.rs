//! Verifies the CLI-to-Power environment boundary.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn power_subprocess_cannot_read_account_or_ambient_secrets() {
    let dir = std::env::temp_dir().join(format!("shimpz-envtest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("child-env.txt");
    let fake_uv = dir.join("uv");
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in shimpz._bridge) export -p > \"{}\"; echo '{{}}' ;; esac; done\nexit 0\n",
        dump.display()
    );
    fs::write(&fake_uv, script).unwrap();
    fs::set_permissions(&fake_uv, fs::Permissions::from_mode(0o755)).unwrap();
    let project = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/assistant");
    let status = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .args(["check", "--project", project])
        .env("SHIMPZ_UV", &fake_uv)
        .env("SHIMPZ_ACCOUNT_CLOUDFLARE", "leaky-token")
        .env("SECRET", "top-secret-value")
        .status()
        .unwrap();
    assert!(status.success(), "check should succeed with the fake uv");
    let seen = fs::read_to_string(&dump).expect("fake uv must have dumped its env");
    assert!(
        !seen.contains("SHIMPZ_ACCOUNT_"),
        "account env leaked to Power:\n{seen}"
    );
    assert!(
        !seen.contains("SECRET"),
        "ambient secret leaked to Power:\n{seen}"
    );
    assert!(
        seen.contains("PATH="),
        "PATH must stay allowlisted for uv:\n{seen}"
    );
}

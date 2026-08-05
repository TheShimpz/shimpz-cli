//! Verifies the CLI-to-Power environment boundary.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const ICON: &str = "iVBORw0KGgoAAAANSUhEUgAABAAAAAQAAQAAAABXZhYuAAAAlklEQVR42u3BAQEAAACCIP+vbkhAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADvBgQeAAEN3jhkAAAAAElFTkSuQmCC";

#[test]
fn power_subprocess_cannot_read_integration_or_ambient_secrets() {
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
    let fixture = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/assistant"
    ));
    let project = dir.join("assistant");
    fs::create_dir_all(project.join("powers")).unwrap();
    for name in ["pyproject.toml", "shimpz.toml"] {
        fs::copy(fixture.join(name), project.join(name)).unwrap();
    }
    for name in ["greet.py", "report.py"] {
        fs::copy(
            fixture.join("powers").join(name),
            project.join("powers").join(name),
        )
        .unwrap();
    }
    fs::write(project.join("icon.png"), BASE64.decode(ICON).unwrap()).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_shimpz"))
        .args(["check", "--project"])
        .arg(&project)
        .env("SHIMPZ_UV", &fake_uv)
        .env("SHIMPZ_INTEGRATION_CLOUDFLARE", "leaky-token")
        .env("SECRET", "top-secret-value")
        .status()
        .unwrap();
    assert!(status.success(), "check should succeed with the fake uv");
    let seen = fs::read_to_string(&dump).expect("fake uv must have dumped its env");
    assert!(
        !seen.contains("SHIMPZ_INTEGRATION_"),
        "integration env leaked to Power:\n{seen}"
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

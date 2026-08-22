//! Verified in-place upgrades for a standalone CLI.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use ureq::{Agent, Body, http::Response};

use crate::output;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const LATEST_URL: &str = "https://github.com/TheShimpz/shimpz-cli/releases/latest";
const RELEASE_DOWNLOAD_ROOT: &str = "https://github.com/TheShimpz/shimpz-cli/releases/download";
const RELEASE_TAG_PATH: &str = "/TheShimpz/shimpz-cli/releases/tag/";
const RELEASE_TAG_URL: &str = "https://github.com/TheShimpz/shimpz-cli/releases/tag/";
const MAX_CHECKSUM_BYTES: u64 = 8 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

struct Release {
    tag: String,
    version: String,
}

pub(crate) fn run() -> Result<String, String> {
    refuse_managed_space_cli()?;
    output::progress("Checking the Standalone CLI release...");
    let latest_agent = agent(true, 0, false);
    let latest = latest_release(&latest_agent)?;
    if !newer_than_current(&latest.version)? {
        return Ok(format!(
            "Standalone shimpz CLI {CURRENT_VERSION} is already up to date."
        ));
    }
    let download_agent = agent(true, 5, true);
    install(&download_agent, &latest)
}

fn refuse_managed_space_cli() -> Result<(), String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let current = std::env::current_exe().ok();
    if managed_space_verdict(cfg!(unix), home.as_deref(), current.as_deref())? {
        return Err(
            "this CLI is managed by Shimpz Space; run shimpz install to reconcile its atomic release"
                .into(),
        );
    }
    Ok(())
}

fn managed_space_verdict(
    unix: bool,
    home: Option<&Path>,
    current: Option<&Path>,
) -> Result<bool, String> {
    let Some(home) = home else {
        return if unix {
            Err("HOME is required to determine whether this CLI is managed".into())
        } else {
            Ok(false)
        };
    };
    if unix && !home.is_absolute() {
        return Err("HOME must be absolute to determine whether this CLI is managed".into());
    }
    let Some(current) = current else {
        return Ok(false);
    };
    Ok(is_managed_space_cli(home, current))
}

fn is_managed_space_cli(home: &Path, current: &Path) -> bool {
    let managed = home.join(".shimpz/bin/shimpz");
    let (Ok(current), Ok(managed)) = (current.canonicalize(), managed.canonicalize()) else {
        return false;
    };
    current == managed
}

fn agent(https_only: bool, max_redirects: u32, redirect_limit_is_error: bool) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .https_only(https_only)
        .max_redirects(max_redirects)
        .max_redirects_will_error(redirect_limit_is_error)
        .http_status_as_error(false)
        .build()
        .into()
}

fn latest_release(agent: &Agent) -> Result<Release, String> {
    let response = agent
        .get(LATEST_URL)
        .header("Accept", "text/html")
        .call()
        .map_err(|_| update_failure("check", None))?;
    if !response.status().is_redirection() {
        return Err(response_failure("check", &response));
    }
    let location = response
        .headers()
        .get("Location")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            "GitHub returned an invalid Standalone CLI release redirect; the CLI was not changed"
                .to_owned()
        })?;
    release_from_location(location)
}

fn release_from_location(location: &str) -> Result<Release, String> {
    let tag = location
        .strip_prefix(RELEASE_TAG_URL)
        .or_else(|| location.strip_prefix(RELEASE_TAG_PATH))
        .filter(|tag| !tag.is_empty() && !tag.contains(['/', '?', '#']))
        .ok_or_else(|| {
            "GitHub returned an invalid Standalone CLI release location; the CLI was not changed"
                .to_owned()
        })?;
    let version = tag
        .strip_prefix('v')
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            "GitHub returned an invalid Standalone CLI release tag; the CLI was not changed"
                .to_owned()
        })?;
    self_update::version::bump_is_greater("0.0.0", version).map_err(|_| {
        "GitHub returned an invalid Standalone CLI release version; the CLI was not changed"
            .to_owned()
    })?;
    Ok(Release {
        tag: tag.to_owned(),
        version: version.to_owned(),
    })
}

fn install(agent: &Agent, release: &Release) -> Result<String, String> {
    let target = self_update::get_target();
    let archive = archive_name(&release.version, target)?;
    let archive_url = download_url(&release.tag, &archive);
    let checksum_url = download_url(&release.tag, "SHA256SUMS");

    output::progress(&format!(
        "Downloading Standalone CLI {} for {target}...",
        release.version
    ));
    let current = std::env::current_exe().map_err(|_| {
        "the Standalone CLI executable path is unavailable; the CLI was not changed".to_owned()
    })?;
    let install_directory = current.parent().ok_or_else(|| {
        "the Standalone CLI install directory is unavailable; the CLI was not changed".to_owned()
    })?;
    let temporary = tempfile::Builder::new()
        .prefix(".shimpz-upgrade-")
        .tempdir_in(install_directory)
        .map_err(|_| {
            "the Standalone CLI cannot stage an update beside the current executable; check directory permissions and retry"
                .to_owned()
        })?;
    let archive_path = temporary.path().join(&archive);
    download(
        agent,
        &archive_url,
        &archive_path,
        MAX_ARCHIVE_BYTES,
        "download",
    )?;

    output::progress("Verifying the Standalone CLI archive...");
    let checksums = fetch_text(agent, &checksum_url, MAX_CHECKSUM_BYTES, "checksum")?;
    let expected = checksum_for(&checksums, &release.version, &archive)?;
    if file_sha256(&archive_path)? != expected {
        return Err(
            "the Standalone CLI archive checksum did not match; the CLI was not changed; retry the upgrade or download the release manually"
                .into(),
        );
    }

    let binary_path = archive_binary_path(&release.version, target);
    self_update::Extract::from_source(&archive_path)
        .extract_file(temporary.path(), &binary_path)
        .map_err(|_| {
            "the verified Standalone CLI archive could not be extracted; the CLI was not changed; download the release manually"
                .to_owned()
        })?;
    let staged = temporary.path().join(&binary_path);
    make_executable(&staged)?;

    output::progress("Installing the verified Standalone CLI...");
    self_update::self_replace::self_replace(&staged).map_err(|_| {
        format!(
            "the Standalone CLI replacement did not complete; download {archive_url}, verify it with {checksum_url}, and replace the command manually"
        )
    })?;
    Ok(format!(
        "Standalone shimpz CLI upgraded from {CURRENT_VERSION} to {}.",
        release.version
    ))
}

fn archive_name(version: &str, target: &str) -> Result<String, String> {
    let extension = match target {
        "x86_64-unknown-linux-gnu"
        | "x86_64-unknown-linux-musl"
        | "aarch64-unknown-linux-gnu"
        | "x86_64-apple-darwin"
        | "aarch64-apple-darwin" => "tar.gz",
        "x86_64-pc-windows-msvc" => "zip",
        _ => {
            return Err(format!(
                "Standalone CLI upgrades are unavailable for target {target}; download a supported release from https://github.com/TheShimpz/shimpz-cli/releases/latest"
            ));
        }
    };
    Ok(format!("shimpz-{version}-{target}.{extension}"))
}

fn archive_binary_path(version: &str, target: &str) -> PathBuf {
    let executable = if target == "x86_64-pc-windows-msvc" {
        "shimpz.exe"
    } else {
        "shimpz"
    };
    PathBuf::from(format!("shimpz-{version}-{target}/{executable}"))
}

fn download_url(tag: &str, asset: &str) -> String {
    format!("{RELEASE_DOWNLOAD_ROOT}/{tag}/{asset}")
}

fn fetch_text(agent: &Agent, url: &str, limit: u64, phase: &'static str) -> Result<String, String> {
    let mut response = request(agent, url, phase)?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|_| update_failure(phase, None))
}

fn download(
    agent: &Agent,
    url: &str,
    destination: &Path,
    limit: u64,
    phase: &'static str,
) -> Result<(), String> {
    let mut response = request(agent, url, phase)?;
    if response
        .headers()
        .get("Content-Length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > limit)
    {
        return Err(update_failure(phase, None));
    }
    let mut source = response.body_mut().with_config().limit(limit).reader();
    let mut target = File::create(destination).map_err(|_| update_failure(phase, None))?;
    std::io::copy(&mut source, &mut target).map_err(|_| update_failure(phase, None))?;
    target.flush().map_err(|_| update_failure(phase, None))
}

fn request(agent: &Agent, url: &str, phase: &'static str) -> Result<Response<Body>, String> {
    let response = agent
        .get(url)
        .header("Accept", "application/octet-stream")
        .call()
        .map_err(|_| update_failure(phase, None))?;
    if response.status().as_u16() == 200 {
        Ok(response)
    } else {
        Err(response_failure(phase, &response))
    }
}

fn response_failure(phase: &'static str, response: &Response<Body>) -> String {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("Retry-After")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=3600).contains(seconds));
    update_failure(
        phase,
        (status == 429 || status == 503)
            .then_some(retry_after)
            .flatten(),
    )
}

fn update_failure(phase: &'static str, retry_after: Option<u64>) -> String {
    let action = retry_after.map_or_else(
        || "retry later".to_owned(),
        |seconds| format!("retry after {seconds} seconds"),
    );
    format!(
        "the Standalone CLI {phase} failed; the CLI was not changed; {action} or download the release from https://github.com/TheShimpz/shimpz-cli/releases/latest"
    )
}

fn checksum_for(document: &str, version: &str, archive: &str) -> Result<String, String> {
    let expected_assets = [
        archive_name(version, "x86_64-unknown-linux-gnu")?,
        archive_name(version, "x86_64-unknown-linux-musl")?,
        archive_name(version, "aarch64-unknown-linux-gnu")?,
        archive_name(version, "x86_64-apple-darwin")?,
        archive_name(version, "aarch64-apple-darwin")?,
        archive_name(version, "x86_64-pc-windows-msvc")?,
    ];
    let mut parsed = BTreeMap::new();
    for line in document.lines() {
        let (digest, name) = line.split_once("  ").ok_or_else(invalid_checksums)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !expected_assets.iter().any(|expected| expected == name)
            || parsed.insert(name, digest.to_owned()).is_some()
        {
            return Err(invalid_checksums());
        }
    }
    if parsed.len() != expected_assets.len()
        || expected_assets
            .iter()
            .any(|expected| !parsed.contains_key(expected.as_str()))
    {
        return Err(invalid_checksums());
    }
    parsed.get(archive).cloned().ok_or_else(invalid_checksums)
}

fn invalid_checksums() -> String {
    "the Standalone CLI checksum manifest is invalid; the CLI was not changed; retry later or download the release manually"
        .into()
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|_| update_failure("verification", None))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| update_failure("verification", None))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = path
        .metadata()
        .map_err(|_| update_failure("installation", None))?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).map_err(|_| update_failure("installation", None))
}

#[cfg(not(unix))]
fn make_executable(path: &Path) -> Result<(), String> {
    path.metadata()
        .map(|_| ())
        .map_err(|_| update_failure("installation", None))
}

fn newer_than_current(version: &str) -> Result<bool, String> {
    self_update::version::bump_is_greater(CURRENT_VERSION, version).map_err(|_| {
        "latest Standalone CLI release has an invalid version; the CLI was not changed".into()
    })
}

#[cfg(test)]
mod tests {
    use flate2::{Compression, write::GzEncoder};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tar::{Builder, Header};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[test]
    fn recognizes_the_managed_cli_without_a_space_marker() {
        let home = tempfile::tempdir().unwrap();
        let managed = home.path().join(".shimpz/bin/shimpz");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::write(&managed, "managed").unwrap();
        let standalone = home.path().join("standalone-shimpz");
        std::fs::write(&standalone, "standalone").unwrap();

        assert!(managed_space_verdict(true, Some(home.path()), Some(&managed)).unwrap());
        assert!(!managed_space_verdict(true, Some(home.path()), Some(&standalone)).unwrap());
        assert!(!managed_space_verdict(true, Some(home.path()), None).unwrap());
        assert!(managed_space_verdict(true, None, Some(&managed)).is_err());
        assert!(!managed_space_verdict(false, None, Some(&managed)).unwrap());
    }

    #[test]
    fn redirect_disabled_agent_returns_the_release_location() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /TheShimpz/shimpz-cli/releases/tag/v9.8.7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let response = agent(false, 0, false)
            .get(format!("http://{address}/latest"))
            .call()
            .unwrap();

        server.join().unwrap();
        assert_eq!(response.status().as_u16(), 302);
        assert_eq!(
            response.headers()["Location"],
            "/TheShimpz/shimpz-cli/releases/tag/v9.8.7"
        );
    }

    #[test]
    fn accepts_only_the_exact_github_latest_location() {
        for location in [
            "/TheShimpz/shimpz-cli/releases/tag/v9.8.7",
            "https://github.com/TheShimpz/shimpz-cli/releases/tag/v9.8.7",
        ] {
            let release = release_from_location(location).unwrap();
            assert_eq!(release.tag, "v9.8.7");
            assert_eq!(release.version, "9.8.7");
        }
        for location in [
            "http://github.com/TheShimpz/shimpz-cli/releases/tag/v9.8.7",
            "https://evil.example/TheShimpz/shimpz-cli/releases/tag/v9.8.7",
            "/TheShimpz/shimpz-cli/releases/tag/v9.8.7?asset=other",
            "/TheShimpz/shimpz-cli/releases/tag/not-semver",
        ] {
            assert!(release_from_location(location).is_err(), "{location}");
        }
    }

    #[test]
    fn checksum_manifest_is_closed_to_the_six_release_archives() {
        let version = "9.8.7";
        let assets = [
            archive_name(version, "x86_64-unknown-linux-gnu").unwrap(),
            archive_name(version, "x86_64-unknown-linux-musl").unwrap(),
            archive_name(version, "aarch64-unknown-linux-gnu").unwrap(),
            archive_name(version, "x86_64-apple-darwin").unwrap(),
            archive_name(version, "aarch64-apple-darwin").unwrap(),
            archive_name(version, "x86_64-pc-windows-msvc").unwrap(),
        ];
        let document = assets
            .iter()
            .enumerate()
            .map(|(index, name)| format!("{:064x}  {name}", index + 1))
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(
            checksum_for(&document, version, &assets[3]).unwrap(),
            format!("{:064x}", 4)
        );
        assert!(checksum_for(&format!("{document}\n{document}"), version, &assets[3]).is_err());
        assert!(
            checksum_for(
                &document.replace(&assets[0], "unexpected.tar.gz"),
                version,
                &assets[3]
            )
            .is_err()
        );
    }

    #[test]
    fn extracts_the_binary_from_each_published_archive_layout() {
        let temporary = tempfile::tempdir().unwrap();
        let version = "9.8.7";
        let cases = [
            ("x86_64-unknown-linux-gnu", "tar.gz"),
            ("x86_64-pc-windows-msvc", "zip"),
        ];

        for (target, extension) in cases {
            let binary = archive_binary_path(version, target);
            assert!(binary.to_str().unwrap().contains('/'));
            let archive = temporary
                .path()
                .join(format!("archive-{target}.{extension}"));
            if extension == "zip" {
                write_zip(&archive, &binary);
            } else {
                write_tar_gz(&archive, &binary);
            }
            let extracted = temporary.path().join(format!("extracted-{target}"));
            std::fs::create_dir(&extracted).unwrap();
            self_update::Extract::from_source(&archive)
                .extract_file(&extracted, &binary)
                .unwrap();
            assert_eq!(std::fs::read(extracted.join(binary)).unwrap(), b"binary");
        }
    }

    fn write_zip(archive: &Path, binary: &Path) {
        let mut writer = ZipWriter::new(File::create(archive).unwrap());
        writer
            .start_file(
                binary.to_str().unwrap(),
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(b"binary").unwrap();
        writer.finish().unwrap();
    }

    fn write_tar_gz(archive: &Path, binary: &Path) {
        let encoder = GzEncoder::new(File::create(archive).unwrap(), Compression::default());
        let mut writer = Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o755);
        header.set_cksum();
        writer
            .append_data(&mut header, binary, &b"binary"[..])
            .unwrap();
        writer.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn download_failures_preserve_bounded_retry_guidance() {
        let rate_limited = update_failure("download", Some(120));
        assert!(rate_limited.contains("retry after 120 seconds"));
        assert!(rate_limited.contains("the CLI was not changed"));
        assert!(!rate_limited.contains('\n'));
    }

    #[cfg(unix)]
    #[test]
    fn recognizes_the_managed_cli_through_its_public_symlink() {
        let home = tempfile::tempdir().unwrap();
        let managed = home.path().join(".shimpz/bin/shimpz");
        let public = home.path().join(".local/bin/shimpz");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::create_dir_all(public.parent().unwrap()).unwrap();
        std::fs::write(&managed, "managed").unwrap();
        std::os::unix::fs::symlink(&managed, &public).unwrap();

        assert!(managed_space_verdict(true, Some(home.path()), Some(&public)).unwrap());
    }

    #[test]
    fn upgrades_only_to_a_newer_semantic_version() {
        assert!(!newer_than_current(CURRENT_VERSION).unwrap());
        assert!(newer_than_current("999.0.0").unwrap());
        assert!(newer_than_current("not-a-version").is_err());
    }
}

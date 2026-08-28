//! Build one unpublished Assistant snapshot in the local Docker daemon.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};
use toml::Value;

use crate::manifest::PublicationIdentity;
use crate::space::command::Tool;
use crate::space::{docker, host, paths::Paths};
use crate::{output, source_package, toolchain};

const PYTHON_VERSION: &str = "3.14";
const LOCAL_STAGE_LABEL: &str = "org.shimpz.local.stage";
const LOCAL_STAGE_VALUE: &str = "assistant-v1";
const ASSISTANT_LABEL: &str = "org.shimpz.assistant.id";
const SOURCE_LABEL: &str = "org.shimpz.source.digest";
const VERSION_LABEL: &str = "org.shimpz.assistant.version";
const BUILD_LABEL: &str = "org.shimpz.local.build.digest";
const MAX_DOCKER_OUTPUT_BYTES: usize = 32 * 1024;
const IMAGE_INSPECT_TEMPLATE: &str = "{{.Id}}\n{{.Architecture}}\n{{json .RepoDigests}}\n{{json .RepoTags}}\n{{index .Config.Labels \"org.shimpz.local.stage\"}}\n{{index .Config.Labels \"org.shimpz.assistant.id\"}}\n{{index .Config.Labels \"org.shimpz.source.digest\"}}\n{{index .Config.Labels \"org.shimpz.assistant.version\"}}\n{{index .Config.Labels \"org.shimpz.local.build.digest\"}}";

const ACTION_RUNNER: &str = r#"#!/opt/shimpz/runtime/bin/python3.14
from __future__ import annotations

import sys

from shimpz._bridge import main as bridge

PROJECT = "/opt/shimpz"


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    return bridge(["invoke", PROJECT, sys.argv[1]])


if __name__ == "__main__":
    raise SystemExit(main())
"#;

const DOCKERFILE: &str = r#"# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS build

WORKDIR /opt/shimpz

COPY --chmod=0444 requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/shimpz/runtime \
    && PIP_ROOT_USER_ACTION=ignore /opt/shimpz/runtime/bin/python3.14 -m pip install \
        --disable-pip-version-check \
        --no-cache-dir \
        --only-binary=:all: \
        --require-hashes \
        --requirement /tmp/requirements.lock \
    && rm /tmp/requirements.lock \
    && rm -rf /root/.cache

COPY --chmod=0555 shimpz_action.py /usr/local/bin/shimpz-action
COPY --chmod=0444 source.package /opt/shimpz/.shimpz/source.package
ADD --chmod=0444 source.package /opt/shimpz/
RUN --network=none /opt/shimpz/runtime/bin/python3.14 -m shimpz._bridge contract /opt/shimpz \
        > /tmp/shimpz.contract.json \
    && mv /tmp/shimpz.contract.json /opt/shimpz/shimpz.contract.json \
    && rm -rf /opt/shimpz/tests \
    && find /opt/shimpz -path /opt/shimpz/runtime -prune -o \
        -type d -exec chmod 0555 {} + \
    && find /opt/shimpz -path /opt/shimpz/runtime -prune -o \
        -type f -exec chmod 0444 {} +

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:0e52dfee02b1aba142e77b004f6ea11210b79456b51f10d70e9bd631cbc21d98

COPY --from=build /usr/local/bin/python3.14 /usr/local/bin/python3.14
COPY --from=build /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=build /usr/local/lib/libpython3.14.so.1.0 /usr/local/lib/libpython3.14.so.1.0
COPY --from=build /usr/local/lib/python3.14/ /usr/local/lib/python3.14/
COPY --from=build /opt/shimpz/ /opt/shimpz/
COPY --from=build /usr/local/bin/shimpz-action /usr/local/bin/shimpz-action

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
ENTRYPOINT ["/opt/shimpz/runtime/bin/python3.14","-c","import signal; signal.pause()"]
"#;

pub(crate) fn run(project: &Path) -> Result<String, String> {
    output::progress("Collecting the exact Assistant source...");
    let package = source_package::build(project)?;
    let identity = PublicationIdentity::parse(&package.manifest)?;
    validate_dependency_sources(&package.pyproject)?;
    let context = tempfile::tempdir().map_err(|_| "Local snapshot workspace cannot be created")?;
    prepare_context(context.path(), &package)?;
    output::progress("Resolving hashed Python dependencies...");
    let requirements = compile_requirements(context.path())?;
    let docker = connect_docker()?;
    let platform = daemon_platform(&docker)?;
    let build_digest = build_digest(&package.bytes, &requirements, platform);
    let image_id = stage_image(
        &docker,
        context.path(),
        &identity,
        &package.digest,
        &build_digest,
        platform,
    )?;
    if let Some(message) = source_package::exclusion_warning(&package) {
        output::warning(&message);
    }
    Ok(format!(
        "Local Assistant snapshot staged.\nAssistant: {} {}\nImage: {}\nNext: open Local Admin and install this unpublished snapshot for a Team.",
        identity.id, identity.version, image_id
    ))
}

fn prepare_context(path: &Path, package: &source_package::SourcePackage) -> Result<(), String> {
    write(path.join("Dockerfile"), DOCKERFILE.as_bytes())?;
    write(path.join("shimpz_action.py"), ACTION_RUNNER.as_bytes())?;
    write(path.join("source.package"), &package.bytes)?;
    write(path.join("pyproject.toml"), &package.pyproject)
}

fn write(path: PathBuf, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|_| "Local snapshot workspace cannot be prepared".into())
}

fn compile_requirements(context: &Path) -> Result<Vec<u8>, String> {
    let requirements = context.join("requirements.lock");
    let result = toolchain::uv()?
        .args([
            "pip",
            "compile",
            "--default-index",
            "https://pypi.org/simple",
            "--generate-hashes",
            "--no-annotate",
            "--no-config",
            "--no-header",
            "--no-sources",
            "--only-binary",
            ":all:",
            "--output-file",
        ])
        .arg(&requirements)
        .args(["--python-version", PYTHON_VERSION, "--universal"])
        .arg(context.join("pyproject.toml"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| "managed uv cannot resolve Local snapshot dependencies")?;
    if !result.status.success() {
        return Err(
            "Local snapshot dependencies require binary packages from the public Python index"
                .into(),
        );
    }
    let bytes =
        fs::read(requirements).map_err(|_| "Local snapshot dependency lock cannot be read")?;
    if bytes.is_empty() {
        return Err("Local snapshot dependency lock is empty".into());
    }
    Ok(bytes)
}

fn connect_docker() -> Result<PathBuf, String> {
    let docker = Tool::Docker.resolve()?;
    let profile = host::detect()?;
    let paths = Paths::discover()?;
    docker::validate_endpoint(&docker, profile, &paths)?;
    require_docker_success(&docker, ["buildx", "version"], "Docker Buildx is required")?;
    require_docker_success(&docker, ["info"], "Docker is unavailable")?;
    Ok(docker)
}

fn daemon_platform(docker: &Path) -> Result<&'static str, String> {
    let result = docker_output(docker, ["info", "--format", "{{.Architecture}}"])?;
    match output_text(&result)?.trim() {
        "amd64" | "x86_64" => Ok("linux/amd64"),
        "arm64" | "aarch64" => Ok("linux/arm64"),
        _ => Err("the Docker daemon architecture is unsupported".into()),
    }
}

fn stage_image(
    docker: &Path,
    context: &Path,
    identity: &PublicationIdentity,
    source_digest: &str,
    build_digest: &str,
    platform: &str,
) -> Result<String, String> {
    if let Some(image_id) = existing_image(docker, build_digest)? {
        output::progress("Reusing the exact Local Assistant snapshot...");
        validate_image(
            docker,
            &image_id,
            identity,
            source_digest,
            build_digest,
            platform,
        )?;
        return Ok(image_id);
    }
    output::progress("Building the Local Assistant snapshot...");
    let image_id = build_image(
        docker,
        context,
        identity,
        source_digest,
        build_digest,
        platform,
    )?;
    validate_image(
        docker,
        &image_id,
        identity,
        source_digest,
        build_digest,
        platform,
    )?;
    Ok(image_id)
}

fn build_image(
    docker: &Path,
    context: &Path,
    identity: &PublicationIdentity,
    source_digest: &str,
    build_digest: &str,
    platform: &str,
) -> Result<String, String> {
    let image_file = tempfile::NamedTempFile::new()
        .map_err(|_| "Local snapshot image identity file cannot be created")?;
    let labels = stage_labels(identity, source_digest, build_digest);
    let mut arguments = vec![
        OsString::from("buildx"),
        OsString::from("build"),
        OsString::from("--load"),
        OsString::from("--provenance=false"),
        OsString::from("--quiet"),
        OsString::from("--sbom=false"),
        OsString::from("--platform"),
        OsString::from(platform),
        OsString::from("--iidfile"),
        image_file.path().as_os_str().to_owned(),
    ];
    for (key, value) in labels {
        arguments.push(OsString::from("--label"));
        arguments.push(OsString::from(format!("{key}={value}")));
    }
    arguments.push(OsString::from("--file"));
    arguments.push(context.join("Dockerfile").into_os_string());
    arguments.push(context.as_os_str().to_owned());
    let result = docker_output(docker, arguments)?;
    if !result.status.success() {
        return Err(docker_failure(&result, "Local snapshot image build failed"));
    }
    let image_id = fs::read_to_string(image_file.path())
        .map_err(|_| "Docker did not return the Local snapshot image identity")?;
    let image_id = image_id.trim().to_owned();
    if !valid_image_id(&image_id) {
        return Err("Docker returned an invalid Local snapshot image identity".into());
    }
    Ok(image_id)
}

fn existing_image(docker: &Path, build_digest: &str) -> Result<Option<String>, String> {
    let filter = format!("label={BUILD_LABEL}={build_digest}");
    let result = docker_output(
        docker,
        [
            "image",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            filter.as_str(),
        ],
    )?;
    if !result.status.success() {
        return Err("Docker could not enumerate cached Local snapshots".into());
    }
    let image_ids = output_text(&result)?
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let [image_id] = image_ids.as_slice() else {
        return if image_ids.is_empty() {
            Ok(None)
        } else {
            Err("Docker returned ambiguous cached Local snapshots".into())
        };
    };
    let image_id = (*image_id).to_owned();
    if !valid_image_id(&image_id) {
        return Err("Docker returned an invalid cached Local snapshot identity".into());
    }
    Ok(Some(image_id))
}

fn validate_image(
    docker: &Path,
    image_id: &str,
    identity: &PublicationIdentity,
    source_digest: &str,
    build_digest: &str,
    platform: &str,
) -> Result<(), String> {
    let result = docker_output(
        docker,
        [
            "image",
            "inspect",
            "--format",
            IMAGE_INSPECT_TEMPLATE,
            image_id,
        ],
    )?;
    let text = output_text(&result)?;
    let fields = text.lines().collect::<Vec<_>>();
    let architecture = platform.rsplit_once('/').map(|(_, value)| value);
    if !result.status.success()
        || fields
            != [
                image_id,
                architecture.unwrap_or_default(),
                "[]",
                "[]",
                LOCAL_STAGE_VALUE,
                identity.id.as_str(),
                source_digest,
                identity.version.as_str(),
                build_digest,
            ]
    {
        return Err("the staged image does not match its Local snapshot contract".into());
    }
    Ok(())
}

fn stage_labels<'a>(
    identity: &'a PublicationIdentity,
    source_digest: &'a str,
    build_digest: &'a str,
) -> BTreeMap<&'static str, &'a str> {
    BTreeMap::from([
        (LOCAL_STAGE_LABEL, LOCAL_STAGE_VALUE),
        (ASSISTANT_LABEL, identity.id.as_str()),
        (SOURCE_LABEL, source_digest),
        (VERSION_LABEL, identity.version.as_str()),
        (BUILD_LABEL, build_digest),
    ])
}

fn build_digest(source: &[u8], requirements: &[u8], platform: &str) -> String {
    let mut digest = Sha256::new();
    for value in [
        b"shimpz-local-stage-v1".as_slice(),
        platform.as_bytes(),
        DOCKERFILE.as_bytes(),
        ACTION_RUNNER.as_bytes(),
        source,
        requirements,
    ] {
        digest.update(value.len().to_be_bytes());
        digest.update(value);
    }
    format!("sha256:{:x}", digest.finalize())
}

fn docker_output<I, S>(docker: &Path, arguments: I) -> Result<Output, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let result = Command::new(docker)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| "Docker could not execute the Local snapshot operation")?;
    if result.stdout.len() > MAX_DOCKER_OUTPUT_BYTES
        || result.stderr.len() > MAX_DOCKER_OUTPUT_BYTES
    {
        return Err("Docker returned excessive Local snapshot output".into());
    }
    Ok(result)
}

fn require_docker_success<I, S>(docker: &Path, arguments: I, message: &str) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let result = docker_output(docker, arguments)?;
    if result.status.success() {
        Ok(())
    } else {
        Err(docker_failure(&result, message))
    }
}

fn output_text(result: &Output) -> Result<&str, String> {
    std::str::from_utf8(&result.stdout)
        .map_err(|_| "Docker returned invalid Local snapshot output".into())
}

fn docker_failure(result: &Output, fallback: &str) -> String {
    let message = String::from_utf8_lossy(&result.stderr);
    let detail = message.lines().rev().find(|line| !line.trim().is_empty());
    detail.map_or_else(
        || fallback.to_owned(),
        |line| format!("{fallback}: {}", line.trim()),
    )
}

fn valid_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_dependency_sources(pyproject: &[u8]) -> Result<(), String> {
    let source = std::str::from_utf8(pyproject).map_err(|_| unsafe_dependencies())?;
    let document = toml::from_str::<Value>(source).map_err(|_| unsafe_dependencies())?;
    let root = document.as_table().ok_or_else(unsafe_dependencies)?;
    if root
        .get("tool")
        .and_then(Value::as_table)
        .and_then(|tool| tool.get("uv"))
        .is_some()
    {
        return Err(unsafe_dependencies());
    }
    if root
        .get("project")
        .and_then(Value::as_table)
        .and_then(|project| project.get("dynamic"))
        .is_some_and(|dynamic| value_names(dynamic, "dependencies"))
    {
        return Err(unsafe_dependencies());
    }
    let project = root.get("project").and_then(Value::as_table);
    let direct = [
        project.and_then(|table| table.get("dependencies")),
        project.and_then(|table| table.get("optional-dependencies")),
        root.get("build-system")
            .and_then(Value::as_table)
            .and_then(|table| table.get("requires")),
        root.get("dependency-groups"),
    ];
    if direct
        .into_iter()
        .flatten()
        .any(contains_direct_requirement)
    {
        return Err(unsafe_dependencies());
    }
    Ok(())
}

fn contains_direct_requirement(value: &Value) -> bool {
    match value {
        Value::String(requirement) => requirement.contains('@'),
        Value::Array(values) => values.iter().any(contains_direct_requirement),
        Value::Table(values) => values.values().any(contains_direct_requirement),
        _ => false,
    }
}

fn value_names(value: &Value, expected: &str) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn unsafe_dependencies() -> String {
    "Local snapshots accept only index-resolved Python dependencies".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_immutable_image_ids() {
        assert!(valid_image_id(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_image_id(&format!("sha256:{}", "g".repeat(64))));
        assert!(!valid_image_id("assistant:latest"));
    }

    #[test]
    fn local_stage_labels_are_distinct_and_bounded() {
        let identity = PublicationIdentity {
            id: "hello-world".into(),
            version: "1.2.3".into(),
            creators: vec!["@creator-one".into()],
        };
        let digest = format!("sha256:{}", "b".repeat(64));
        let build = format!("sha256:{}", "c".repeat(64));
        assert_eq!(
            stage_labels(&identity, &digest, &build),
            BTreeMap::from([
                (LOCAL_STAGE_LABEL, LOCAL_STAGE_VALUE),
                (ASSISTANT_LABEL, "hello-world"),
                (SOURCE_LABEL, digest.as_str()),
                (VERSION_LABEL, "1.2.3"),
                (BUILD_LABEL, build.as_str()),
            ])
        );
    }

    #[test]
    fn exact_build_inputs_have_one_stable_cache_identity() {
        let one = build_digest(b"source", b"requirements", "linux/amd64");
        assert_eq!(one, build_digest(b"source", b"requirements", "linux/amd64"));
        assert_ne!(
            one,
            build_digest(b"changed", b"requirements", "linux/amd64")
        );
        assert_ne!(one, build_digest(b"source", b"requirements", "linux/arm64"));
    }

    #[test]
    fn rejects_custom_and_direct_dependency_sources() {
        for source in [
            "[project]\ndependencies = [\"private @ https://example.test/private.whl\"]\n",
            "[project]\ndynamic = [\"dependencies\"]\n",
            "[tool.uv.sources]\nprivate = { path = \"../private\" }\n",
            "[dependency-groups]\ndev = [\"private @ git+https://example.test/repo\"]\n",
        ] {
            assert!(validate_dependency_sources(source.as_bytes()).is_err());
        }
        assert!(
            validate_dependency_sources(
                b"[project]\nauthors = [{ email = \"creator@example.test\" }]\ndependencies = [\"shimpz==0.4.1\", \"httpx>=0.28\"]\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn local_builder_has_no_publication_or_space_authority() {
        let source = include_str!("stage.rs");
        let implementation = source.split("#[cfg(test)]").next().unwrap();
        assert!(!implementation.contains("ensure_authenticated"));
        assert!(!implementation.contains("developers.shimpz.com"));
        assert!(!implementation.contains("lifecycle::"));
        assert!(!implementation.contains("credentials"));
    }
}

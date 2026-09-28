//! Build one unpublished Assistant snapshot in the local Docker daemon.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::hash::{BuildHasher, RandomState};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use toml::Value;

use crate::manifest::{self, PublicationIdentity};
use crate::space::command::Tool;
use crate::space::{docker, host, paths::Paths};
use crate::{output, snapshot_lock, source_package, toolchain};

const PYTHON_VERSION: &str = "3.14";
pub(crate) const LOCAL_STAGE_LABEL: &str = "org.shimpz.local.stage";
pub(crate) const LOCAL_STAGE_VALUE: &str = "assistant-v3";
pub(crate) const ASSISTANT_LABEL: &str = "org.shimpz.assistant.id";
const NAME_LABEL: &str = "org.shimpz.assistant.name";
const SUMMARY_LABEL: &str = "org.shimpz.assistant.summary";
const DECLARED_CREATORS_LABEL: &str = "org.shimpz.assistant.declared-creators";
const SOURCE_LABEL: &str = "org.shimpz.source.digest";
const VERSION_LABEL: &str = "org.shimpz.assistant.version";
const BUILD_LABEL: &str = "org.shimpz.local.build.digest";
const ACTIONS_LABEL: &str = "org.shimpz.assistant.actions";
const INTEGRATIONS_LABEL: &str = "org.shimpz.assistant.integrations";
const NONCE_LABEL: &str = "org.shimpz.local.stage.nonce";
/// The one tag that makes a staged image its Assistant's current snapshot; untagged staged images are superseded.
pub(crate) const LOCAL_SNAPSHOT_REPOSITORY: &str = "shimpz-local";
pub(crate) const LOCAL_SNAPSHOT_TAG: &str = "staged";
const CURRENT_INSPECT_TEMPLATE: &str = "{{.Id}}\n{{json .RepoDigests}}\n{{json .RepoTags}}\n{{index .Config.Labels \"org.shimpz.local.stage\"}}\n{{index .Config.Labels \"org.shimpz.assistant.id\"}}\n{{index .Config.Labels \"org.shimpz.local.build.digest\"}}\n{{index .Config.Labels \"org.shimpz.local.stage.nonce\"}}";
const MAX_DOCKER_OUTPUT_BYTES: usize = 32 * 1024;
const IMAGE_INSPECT_TEMPLATE: &str = "{{.Id}}\n{{.Architecture}}\n{{json .RepoDigests}}\n{{json .RepoTags}}\n{{index .Config.Labels \"org.shimpz.local.stage\"}}\n{{index .Config.Labels \"org.shimpz.assistant.id\"}}\n{{index .Config.Labels \"org.shimpz.assistant.name\"}}\n{{index .Config.Labels \"org.shimpz.assistant.summary\"}}\n{{index .Config.Labels \"org.shimpz.assistant.declared-creators\"}}\n{{index .Config.Labels \"org.shimpz.source.digest\"}}\n{{index .Config.Labels \"org.shimpz.assistant.version\"}}\n{{index .Config.Labels \"org.shimpz.local.build.digest\"}}\n{{index .Config.Labels \"org.shimpz.assistant.actions\"}}\n{{index .Config.Labels \"org.shimpz.assistant.integrations\"}}";

struct DiscoveryProjection {
    actions: Vec<String>,
    integrations: Vec<String>,
}

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
    let _lock = snapshot_lock::acquire(&identity.id)?;
    let discovery = DiscoveryProjection {
        actions: action_ids(&package.action_files)?,
        integrations: manifest::integration_ids(&package.manifest)?,
    };
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
        &discovery,
    )?;
    if let Some(message) = source_package::exclusion_warning(&package) {
        output::warning(&message);
    }
    Ok(format!(
        "Local Assistant snapshot staged.\nAssistant: {} {}\nImage: {}\nEarlier snapshots of this Assistant are removed by the Local Space once no Team uses them.\nNext: ask a Local Team for work that needs this Assistant. Chat installs a fresh binding automatically; existing bindings still require an explicit replacement in Admin.",
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
    let docker = connect_docker_daemon()?;
    require_docker_success(&docker, ["buildx", "version"], "Docker Buildx is required")?;
    Ok(docker)
}

pub(crate) fn connect_docker_daemon() -> Result<PathBuf, String> {
    let docker = Tool::Docker.resolve()?;
    let profile = host::detect()?;
    let paths = Paths::discover()?;
    docker::validate_endpoint(&docker, profile, &paths)?;
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

pub(crate) fn canonical_reference(assistant_id: &str) -> String {
    format!("{LOCAL_SNAPSHOT_REPOSITORY}/{assistant_id}:{LOCAL_SNAPSHOT_TAG}")
}

/// A never-pulled snapshot has no digest, or, on a containerd image store, only its own local digest.
fn local_digests_valid(digests: &str, assistant_id: &str, image_id: &str) -> bool {
    digests == "[]"
        || digests == format!("[\"{LOCAL_SNAPSHOT_REPOSITORY}/{assistant_id}@{image_id}\"]")
}

fn stage_image(
    docker: &Path,
    context: &Path,
    identity: &PublicationIdentity,
    source_digest: &str,
    build_digest: &str,
    platform: &str,
    discovery: &DiscoveryProjection,
) -> Result<String, String> {
    let reference = canonical_reference(&identity.id);
    let current = current_image(docker, &reference, &identity.id)?;
    let expected = ExpectedImage {
        reference: &reference,
        identity,
        source_digest,
        build_digest,
        platform,
        discovery,
    };
    if let Some(current) = current
        .as_ref()
        .filter(|current| current.build_digest == build_digest)
    {
        output::progress("Reusing the current Local Assistant snapshot...");
        validate_image(docker, &current.image_id, &expected)?;
        require_current(docker, &reference, &current.image_id)?;
        return Ok(current.image_id.clone());
    }
    output::progress("Building the Local Assistant snapshot...");
    // The build loads the image already tagged, so a new snapshot never exists untagged and the Local Space
    // can never collect it; the previous current snapshot loses the tag in the same step.
    // A failure anywhere after the build may already have moved the tag, so every one reconciles it; the nonce
    // proves which tagged image this attempt produced.
    let nonce = stage_nonce();
    build_image(docker, context, &expected, &nonce)
        .and_then(|image_id| {
            validate_image(docker, &image_id, &expected)?;
            require_current(docker, &reference, &image_id)?;
            Ok(image_id)
        })
        .map_err(|error| {
            reconcile_current(
                docker,
                &reference,
                &identity.id,
                current.as_ref(),
                &nonce,
                &error,
            )
        })
}

struct ExpectedImage<'a> {
    reference: &'a str,
    identity: &'a PublicationIdentity,
    source_digest: &'a str,
    build_digest: &'a str,
    platform: &'a str,
    discovery: &'a DiscoveryProjection,
}

struct CurrentImage {
    image_id: String,
    build_digest: String,
    nonce: String,
}

/// Resolve the Assistant's tag, refusing to overwrite a tag that points outside this Assistant's snapshots.
fn current_image(
    docker: &Path,
    reference: &str,
    assistant_id: &str,
) -> Result<Option<CurrentImage>, String> {
    let result = docker_output(
        docker,
        [
            "image",
            "inspect",
            "--format",
            CURRENT_INSPECT_TEMPLATE,
            reference,
        ],
    )?;
    if !result.status.success() {
        let detail = String::from_utf8_lossy(&result.stderr);
        if detail.contains("No such image") || detail.contains("No such object") {
            return Ok(None);
        }
        return Err(docker_failure(
            &result,
            "Docker could not resolve the current Local snapshot",
        ));
    }
    let text = output_text(&result)?;
    let fields = text.lines().collect::<Vec<_>>();
    let expected_tags = format!("[\"{reference}\"]");
    match fields.as_slice() {
        [
            image_id,
            digests,
            tags,
            LOCAL_STAGE_VALUE,
            owner,
            build_digest,
            nonce,
        ] if valid_image_id(image_id)
            && local_digests_valid(digests, assistant_id, image_id)
            && *tags == expected_tags
            && *owner == assistant_id
            && valid_image_id(build_digest) =>
        {
            Ok(Some(CurrentImage {
                image_id: (*image_id).to_owned(),
                build_digest: (*build_digest).to_owned(),
                nonce: (*nonce).to_owned(),
            }))
        }
        _ => Err(format!(
            "the tag {reference} points to an image outside this Assistant's Local snapshots; remove that tag, then stage again"
        )),
    }
}

fn require_current(docker: &Path, reference: &str, image_id: &str) -> Result<(), String> {
    let result = docker_output(
        docker,
        ["image", "inspect", "--format", "{{.Id}}", reference],
    )?;
    if result.status.success() && output_text(&result)?.trim() == image_id {
        Ok(())
    } else {
        Err("the staged image did not become this Assistant's current Local snapshot".into())
    }
}

/// After a failed stage, undo only this attempt's own tag move: re-tag the previous snapshot, or remove the image
/// this attempt tagged. A tag that another actor moved, removed, or that cannot be read is left untouched.
fn reconcile_current(
    docker: &Path,
    reference: &str,
    assistant_id: &str,
    previous: Option<&CurrentImage>,
    nonce: &str,
    error: &str,
) -> String {
    let Ok(tagged) = current_image(docker, reference, assistant_id) else {
        return format!(
            "{error}; {reference} could not be read, so check it before rerunning 'shimpz assistant stage'"
        );
    };
    let own = tagged.as_ref().filter(|tagged| tagged.nonce == nonce);
    match (previous, tagged.as_ref(), own) {
        (Some(previous), Some(tagged), _) if tagged.image_id == previous.image_id => {
            format!("{error}; the previous Local snapshot remains current")
        }
        (Some(previous), _, Some(_)) => {
            if docker_succeeds(docker, ["tag", previous.image_id.as_str(), reference]) {
                format!("{error}; the previous Local snapshot remains current")
            } else {
                format!(
                    "{error}; the previous Local snapshot could not be made current again, so rerun 'shimpz assistant stage'"
                )
            }
        }
        (None, _, Some(own)) => {
            if docker_succeeds(docker, ["image", "rm", "--no-prune", own.image_id.as_str()]) {
                format!("{error}; the invalid snapshot was removed")
            } else {
                format!(
                    "{error}; the invalid snapshot could not be removed, so run 'shimpz assistant unstage' before staging again"
                )
            }
        }
        (None, None, None) => error.to_owned(),
        _ => {
            format!("{error}; {reference} was changed by another staging, so it was left as it is")
        }
    }
}

fn docker_succeeds<I, S>(docker: &Path, arguments: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    matches!(docker_output(docker, arguments), Ok(result) if result.status.success())
}

fn build_image(
    docker: &Path,
    context: &Path,
    expected: &ExpectedImage,
    nonce: &str,
) -> Result<String, String> {
    let image_file = tempfile::NamedTempFile::new()
        .map_err(|_| "Local snapshot image identity file cannot be created")?;
    let mut labels = stage_labels(
        expected.identity,
        expected.source_digest,
        expected.build_digest,
        expected.discovery,
    );
    // A unique label gives every non-reused stage a new image, never one the Local Space already treats as superseded.
    labels.insert(NONCE_LABEL, nonce.to_owned());
    let mut arguments = vec![
        OsString::from("buildx"),
        OsString::from("build"),
        OsString::from("--load"),
        OsString::from("--provenance=false"),
        OsString::from("--quiet"),
        OsString::from("--sbom=false"),
        OsString::from("--platform"),
        OsString::from(expected.platform),
        OsString::from("--tag"),
        OsString::from(expected.reference),
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

fn stage_nonce() -> String {
    let mut digest = Sha256::new();
    digest.update(RandomState::new().hash_one(process::id()).to_be_bytes());
    digest.update(process::id().to_be_bytes());
    digest.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_be_bytes(),
    );
    format!("{:x}", digest.finalize())[..32].to_owned()
}

fn validate_image(docker: &Path, image_id: &str, expected: &ExpectedImage) -> Result<(), String> {
    let identity = expected.identity;
    let declared_creators = declared_creators(identity);
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
    let architecture = expected.platform.rsplit_once('/').map(|(_, value)| value);
    let tags = format!("[\"{}\"]", expected.reference);
    let digests = fields.get(2).copied().unwrap_or_default();
    if !result.status.success()
        || !local_digests_valid(digests, &identity.id, image_id)
        || fields
            != [
                image_id,
                architecture.unwrap_or_default(),
                digests,
                tags.as_str(),
                LOCAL_STAGE_VALUE,
                identity.id.as_str(),
                identity.name.as_str(),
                identity.summary.as_str(),
                declared_creators.as_str(),
                expected.source_digest,
                identity.version.as_str(),
                expected.build_digest,
                expected.discovery.actions.join(",").as_str(),
                expected.discovery.integrations.join(",").as_str(),
            ]
    {
        return Err("the staged image does not match its Local snapshot contract".into());
    }
    Ok(())
}

fn stage_labels(
    identity: &PublicationIdentity,
    source_digest: &str,
    build_digest: &str,
    discovery: &DiscoveryProjection,
) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (LOCAL_STAGE_LABEL, LOCAL_STAGE_VALUE.into()),
        (ASSISTANT_LABEL, identity.id.clone()),
        (NAME_LABEL, identity.name.clone()),
        (SUMMARY_LABEL, identity.summary.clone()),
        (DECLARED_CREATORS_LABEL, declared_creators(identity)),
        (SOURCE_LABEL, source_digest.into()),
        (VERSION_LABEL, identity.version.clone()),
        (BUILD_LABEL, build_digest.into()),
        (ACTIONS_LABEL, discovery.actions.join(",")),
        (INTEGRATIONS_LABEL, discovery.integrations.join(",")),
    ])
}

fn action_ids(files: &[String]) -> Result<Vec<String>, String> {
    let mut actions = files
        .iter()
        .filter_map(|file| file.strip_suffix(".py"))
        .map(|stem| stem.replace('_', "-"))
        .collect::<Vec<_>>();
    actions.sort();
    if actions.is_empty()
        || actions.len() > 128
        || actions
            .iter()
            .any(|action| !manifest::valid_action_id(action))
        || actions.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err("Assistant Action identities are invalid".into());
    }
    Ok(actions)
}

fn declared_creators(identity: &PublicationIdentity) -> String {
    identity
        .creators
        .iter()
        .take(4)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn build_digest(source: &[u8], requirements: &[u8], platform: &str) -> String {
    let mut digest = Sha256::new();
    for value in [
        b"shimpz-local-stage-v3".as_slice(),
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

pub(crate) fn valid_image_id(value: &str) -> bool {
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

/// Wait until a freshly written fake executable can run: a parallel test's fork can briefly hold it open for writing.
#[cfg(all(test, unix))]
pub(crate) fn await_executable(path: &Path) {
    for _ in 0..200 {
        match Command::new(path).output() {
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            _ => return,
        }
    }
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
            name: "Hello world".into(),
            summary: "A local Assistant snapshot.".into(),
        };
        let digest = format!("sha256:{}", "b".repeat(64));
        let build = format!("sha256:{}", "c".repeat(64));
        assert_eq!(
            stage_labels(
                &identity,
                &digest,
                &build,
                &DiscoveryProjection {
                    actions: vec!["list-items".into(), "send-message".into()],
                    integrations: vec!["whatsapp".into()],
                }
            ),
            BTreeMap::from([
                (LOCAL_STAGE_LABEL, LOCAL_STAGE_VALUE.into()),
                (ASSISTANT_LABEL, "hello-world".into()),
                (NAME_LABEL, "Hello world".into()),
                (SUMMARY_LABEL, "A local Assistant snapshot.".into()),
                (DECLARED_CREATORS_LABEL, "@creator-one".into()),
                (SOURCE_LABEL, digest),
                (VERSION_LABEL, "1.2.3".into()),
                (BUILD_LABEL, build),
                (ACTIONS_LABEL, "list-items,send-message".into()),
                (INTEGRATIONS_LABEL, "whatsapp".into()),
            ])
        );
    }

    #[test]
    fn derives_canonical_action_ids_for_discovery() {
        assert_eq!(
            action_ids(&["send_message.py".into(), "list-zones.py".into()]),
            Ok(vec!["list-zones".into(), "send-message".into()])
        );
        assert!(action_ids(&["same_name.py".into(), "same-name.py".into()]).is_err());
        assert!(action_ids(&[]).is_err());
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
                b"[project]\nauthors = [{ email = \"creator@example.test\" }]\ndependencies = [\"shimpz==0.4.2\", \"httpx>=0.28\"]\n"
            )
            .is_ok()
        );
    }

    #[cfg(unix)]
    fn fake_docker(directory: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let executable = directory.join("docker-proof");
        fs::write(&executable, format!("#!/bin/sh\n{body}\nexit 2\n")).expect("fake Docker");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable fake Docker");
        await_executable(&executable);
        executable
    }

    fn proof_identity() -> PublicationIdentity {
        PublicationIdentity {
            id: "proof-assistant".into(),
            version: "1.0.0".into(),
            creators: vec!["@creator".into()],
            name: "Proof".into(),
            summary: "Proves staging.".into(),
        }
    }

    fn image(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    /// The fields `validate_image` expects for `image_id` when it carries the Assistant's tag.
    fn contract_fields(image_id: &str, build: &str) -> String {
        [
            image_id,
            "amd64",
            "[]",
            "[\"shimpz-local/proof-assistant:staged\"]",
            LOCAL_STAGE_VALUE,
            "proof-assistant",
            "Proof",
            "Proves staging.",
            "@creator",
            &image('d'),
            "1.0.0",
            build,
            "ping",
            "",
        ]
        .join("\\n")
    }

    fn stage_proof(docker: &Path, context: &Path, build: &str) -> Result<String, String> {
        let identity = proof_identity();
        stage_image(
            docker,
            context,
            &identity,
            &image('d'),
            build,
            "linux/amd64",
            &DiscoveryProjection {
                actions: vec!["ping".into()],
                integrations: Vec::new(),
            },
        )
    }

    #[cfg(unix)]
    #[test]
    fn resolves_only_this_assistants_current_tag() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let reference = canonical_reference("proof-assistant");
        assert_eq!(reference, "shimpz-local/proof-assistant:staged");
        let absent = fake_docker(
            directory.path(),
            "printf 'Error response from daemon: No such image: x\\n' >&2; exit 1",
        );
        assert!(
            current_image(&absent, &reference, "proof-assistant")
                .expect("absent")
                .is_none()
        );

        for (tags, owner, digests) in [
            (
                "[\\\"shimpz-local/proof-assistant:staged\\\"]",
                "other-assistant",
                "[]",
            ),
            (
                "[\\\"shimpz-local/proof-assistant:staged\\\",\\\"extra:tag\\\"]",
                "proof-assistant",
                "[]",
            ),
            (
                "[\\\"shimpz-local/proof-assistant:staged\\\"]",
                "proof-assistant",
                "[\\\"registry/x@sha256:1\\\"]",
            ),
        ] {
            let foreign = fake_docker(
                directory.path(),
                &format!(
                    "printf '%s\\n' '{}' '{digests}' '{tags}' '{LOCAL_STAGE_VALUE}' '{owner}' '{}' 'nonce'; exit 0",
                    image('a'),
                    image('b')
                ),
            );
            let error = current_image(&foreign, &reference, "proof-assistant")
                .err()
                .expect("foreign tag");
            assert!(
                error.contains("outside this Assistant's Local snapshots"),
                "{error}"
            );
        }

        let docker_error = fake_docker(directory.path(), "printf 'daemon offline\\n' >&2; exit 1");
        assert!(current_image(&docker_error, &reference, "proof-assistant").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn an_identical_current_snapshot_is_reused_without_building_or_retagging() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let calls = directory.path().join("calls");
        let current = image('a');
        let build = image('b');
        let docker = fake_docker(
            directory.path(),
            &format!(
                "printf '%s\\n' \"$*\" >> '{calls}'\n\
                 case \"$4\" in *Architecture*) printf '{fields}\\n'; exit 0;; '{{{{.Id}}}}') printf '%s\\n' '{current}'; exit 0;; esac\n\
                 printf '%s\\n' '{current}' '[]' '[\"shimpz-local/proof-assistant:staged\"]' '{LOCAL_STAGE_VALUE}' 'proof-assistant' '{build}' 'earlier-nonce'; exit 0",
                calls = calls.display(),
                fields = contract_fields(&current, &build),
            ),
        );
        assert_eq!(stage_proof(&docker, directory.path(), &build), Ok(current));
        let calls = fs::read_to_string(calls).expect("calls");
        assert!(!calls.contains("buildx"));
        assert!(!calls.lines().any(|call| call.starts_with("tag ")));
    }

    #[cfg(unix)]
    #[test]
    fn a_changed_snapshot_is_built_already_tagged_and_becomes_current() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let calls = directory.path().join("calls");
        let previous = image('a');
        let built = image('c');
        let build_digest = image('b');
        let docker = fake_docker(
            directory.path(),
            &format!(
                "printf '%s\\n' \"$*\" >> '{calls}'\n\
                 if [ \"$1\" = buildx ]; then while [ \"$#\" -gt 0 ]; do [ \"$1\" = --iidfile ] && printf '%s' '{built}' > \"$2\"; shift; done; exit 0; fi\n\
                 case \"$4\" in *Architecture*) printf '{fields}\\n'; exit 0;; '{{{{.Id}}}}') printf '%s\\n' '{built}'; exit 0;; esac\n\
                 printf '%s\\n' '{previous}' '[]' '[\"shimpz-local/proof-assistant:staged\"]' '{LOCAL_STAGE_VALUE}' 'proof-assistant' '{old}' 'earlier-nonce'; exit 0",
                calls = calls.display(),
                fields = contract_fields(&built, &build_digest),
                old = image('e'),
            ),
        );
        assert_eq!(
            stage_proof(&docker, directory.path(), &build_digest),
            Ok(built)
        );
        let calls = fs::read_to_string(calls).expect("calls");
        let build_call = calls
            .lines()
            .find(|call| call.starts_with("buildx build"))
            .expect("build");
        assert!(build_call.contains("--tag shimpz-local/proof-assistant:staged"));
        assert!(build_call.contains("--label org.shimpz.local.stage.nonce="));
        assert!(!calls.lines().any(|call| call.starts_with("tag ")));
    }

    /// A fake daemon whose canonical tag moves to the built image on load, like `buildx build --load --tag`,
    /// unless `intruder` makes another stage's image take the tag while this build fails without loading.
    #[cfg(unix)]
    fn moving_tag_docker(
        directory: &Path,
        previous: Option<&str>,
        build_exit: u8,
        mutation_exit: u8,
        intruder: bool,
    ) -> (PathBuf, PathBuf) {
        let calls = directory.join("calls");
        let moved = directory.join("moved");
        let nonce = directory.join("nonce");
        for file in [&calls, &moved, &nonce] {
            let _ = fs::remove_file(file);
        }
        let built = image('c');
        let owned = |id: &str, stage_nonce: &str| {
            format!(
                "printf '%s\\n' '{id}' '[]' '[\"shimpz-local/proof-assistant:staged\"]' '{LOCAL_STAGE_VALUE}' 'proof-assistant' '{}' {stage_nonce}; exit 0",
                image('e')
            )
        };
        let before = previous.map_or_else(
            || "printf 'No such image\\n' >&2; exit 1".to_owned(),
            |id| owned(id, "'earlier-nonce'"),
        );
        let load = if intruder {
            format!("printf '%s' '{}' > '{}'", image('f'), moved.display())
        } else {
            format!("printf '%s' '{built}' > '{}'", moved.display())
        };
        let script = format!(
            "printf '%s\\n' \"$*\" >> '{calls}'\n\
             if [ \"$1\" = buildx ]; then {load}; while [ \"$#\" -gt 0 ]; do case \"$1\" in org.shimpz.local.stage.nonce=*) printf '%s' \"${{1#*=}}\" > '{nonce}';; --iidfile) printf '%s' '{built}' > \"$2\";; esac; shift; done; exit {build_exit}; fi\n\
             if [ \"$1\" = tag ] || [ \"$2\" = rm ]; then [ {mutation_exit} = 0 ] && rm -f '{moved}'; exit {mutation_exit}; fi\n\
             case \"$4\" in *Architecture*) printf 'wrong\\n'; exit 0;; esac\n\
             if [ -f '{moved}' ] && [ \"$(cat '{moved}')\" = '{built}' ]; then {ours}; fi\n\
             if [ -f '{moved}' ]; then {theirs}; fi\n\
             {before}",
            calls = calls.display(),
            moved = moved.display(),
            nonce = nonce.display(),
            ours = owned(&built, &format!("\"$(cat '{}')\"", nonce.display())),
            theirs = owned(&image('f'), "'another-stage'"),
        );
        (fake_docker(directory, &script), calls)
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_stage_reconciles_only_its_own_tag_move() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let previous = image('a');
        let built = image('c');
        for (build_exit, mutation_exit, has_previous, expected) in [
            (0, 0, true, "the previous Local snapshot remains current"),
            (0, 1, true, "could not be made current again"),
            (1, 0, true, "the previous Local snapshot remains current"),
            (0, 0, false, "the invalid snapshot was removed"),
            (1, 0, false, "the invalid snapshot was removed"),
            (0, 1, false, "run 'shimpz assistant unstage'"),
        ] {
            let (docker, calls) = moving_tag_docker(
                directory.path(),
                has_previous.then_some(previous.as_str()),
                build_exit,
                mutation_exit,
                false,
            );
            let error = stage_proof(&docker, directory.path(), &image('b')).unwrap_err();
            assert!(error.contains(expected), "{error}");
            let calls = fs::read_to_string(&calls).expect("calls");
            if has_previous {
                assert!(calls.contains(&format!(
                    "tag {previous} shimpz-local/proof-assistant:staged"
                )));
            } else {
                assert!(calls.contains(&format!("image rm --no-prune {built}")));
            }
        }

        for has_previous in [true, false] {
            let (docker, calls) = moving_tag_docker(
                directory.path(),
                has_previous.then_some(previous.as_str()),
                1,
                0,
                true,
            );
            let error = stage_proof(&docker, directory.path(), &image('b')).unwrap_err();
            assert!(error.contains("changed by another staging"), "{error}");
            let calls = fs::read_to_string(&calls).expect("calls");
            assert!(
                !calls
                    .lines()
                    .any(|call| call.starts_with("tag ") || call.starts_with("image rm"))
            );
        }

        let unreadable = fake_docker(directory.path(), "printf 'daemon offline\\n' >&2; exit 1");
        let identity = proof_identity();
        let error = reconcile_current(
            &unreadable,
            &canonical_reference(&identity.id),
            &identity.id,
            None,
            "nonce",
            "build failed",
        );
        assert!(error.contains("could not be read"), "{error}");
    }

    #[test]
    fn accepts_only_a_never_pulled_snapshot_digest() {
        let id = image('a');
        assert!(local_digests_valid("[]", "proof-assistant", &id));
        assert!(local_digests_valid(
            &format!("[\"shimpz-local/proof-assistant@{id}\"]"),
            "proof-assistant",
            &id
        ));
        for digests in [
            format!("[\"ghcr.io/theshimpz/shimpz-assistant@{id}\"]"),
            format!("[\"shimpz-local/other-assistant@{id}\"]"),
            format!("[\"shimpz-local/proof-assistant@{}\"]", image('b')),
        ] {
            assert!(
                !local_digests_valid(&digests, "proof-assistant", &id),
                "{digests}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_containerd_current_snapshot_is_reused_with_its_local_digest() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let current = image('a');
        let build = image('b');
        let local = format!("[\"shimpz-local/proof-assistant@{current}\"]");
        let fields = contract_fields(&current, &build).replacen("[]", &local, 1);
        let docker = fake_docker(
            directory.path(),
            &format!(
                "case \"$4\" in *Architecture*) printf '{fields}\\n'; exit 0;; '{{{{.Id}}}}') printf '%s\\n' '{current}'; exit 0;; esac\n\
                 printf '%s\\n' '{current}' '{local}' '[\"shimpz-local/proof-assistant:staged\"]' '{LOCAL_STAGE_VALUE}' 'proof-assistant' '{build}' 'earlier-nonce'; exit 0"
            ),
        );
        assert_eq!(stage_proof(&docker, directory.path(), &build), Ok(current));
    }

    #[test]
    fn every_stage_carries_a_distinct_nonce() {
        let first = stage_nonce();
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, stage_nonce());
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

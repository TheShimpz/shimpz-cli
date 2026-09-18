//! Permanently remove unpublished Assistant snapshots from the local Docker daemon.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::manifest::PublicationIdentity;
use crate::{output, source_package, stage};

const MAX_BATCH: usize = 50;
const MAX_DOCKER_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FAILURE_DETAIL_CHARS: usize = 240;
const INSPECT_TEMPLATE: &str = "{{.Id}}\n{{index .Config.Labels \"org.shimpz.local.stage\"}}\n{{index .Config.Labels \"org.shimpz.assistant.id\"}}";

pub(crate) fn run(project: &Path) -> Result<String, String> {
    let manifest = source_package::read_manifest(project)?;
    let identity = PublicationIdentity::parse(&manifest)?;
    let docker = stage::connect_docker_daemon()?;
    let removed = remove_all(&docker, &identity.id)?;
    Ok(removal_success(&identity.id, removed))
}

fn remove_all(docker: &Path, assistant_id: &str) -> Result<usize, String> {
    let mut removed = 0_usize;
    let mut previous_batch = BTreeSet::new();
    loop {
        let images = staged_images(docker, assistant_id)?;
        if images.is_empty() {
            return Ok(removed);
        }
        if images.iter().any(|image| previous_batch.contains(image)) {
            return Err(
                "Docker reported successful Local snapshot removal without converging; inspect the daemon state and rerun 'shimpz assistant unstage'"
                    .into(),
            );
        }
        validate_images(docker, assistant_id, &images)?;
        if removed == 0 {
            output::progress("Removing the Local Assistant snapshots...");
        }
        let batch = images.iter().cloned().collect();
        removed += remove_images(docker, assistant_id, &images)?;
        previous_batch = batch;
    }
}

fn staged_images(docker: &Path, assistant_id: &str) -> Result<Vec<String>, String> {
    let stage_filter = format!(
        "label={}={}",
        stage::LOCAL_STAGE_LABEL,
        stage::LOCAL_STAGE_VALUE
    );
    let assistant_filter = format!("label={}={assistant_id}", stage::ASSISTANT_LABEL);
    let result = docker_output(
        docker,
        [
            "image",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            stage_filter.as_str(),
            "--filter",
            assistant_filter.as_str(),
        ],
    )?;
    if !result.status.success() {
        return Err("Docker could not enumerate Local Assistant snapshots".into());
    }
    Ok(canonical_image_ids(output_text(&result)?)?
        .into_iter()
        .take(MAX_BATCH)
        .collect())
}

fn canonical_image_ids(output: &str) -> Result<Vec<String>, String> {
    let images = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if images.iter().any(|image| !stage::valid_image_id(image)) {
        return Err("Docker returned an invalid Local Assistant snapshot inventory".into());
    }
    Ok(images
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn validate_images(docker: &Path, assistant_id: &str, images: &[String]) -> Result<(), String> {
    for image_id in images {
        let result = docker_output(
            docker,
            ["image", "inspect", "--format", INSPECT_TEMPLATE, image_id],
        )?;
        let expected = [image_id.as_str(), stage::LOCAL_STAGE_VALUE, assistant_id];
        if !result.status.success() || output_text(&result)?.lines().collect::<Vec<_>>() != expected
        {
            return Err(
                "a Local Assistant snapshot changed before removal; no image was removed".into(),
            );
        }
    }
    Ok(())
}

fn remove_images(docker: &Path, assistant_id: &str, images: &[String]) -> Result<usize, String> {
    let mut remaining = Vec::new();
    let mut first_failure = None;
    for image_id in images {
        match docker_output(docker, ["image", "rm", "--no-prune", image_id.as_str()]) {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                remaining.push(image_id.as_str());
                first_failure.get_or_insert_with(|| docker_failure_detail(&result));
            }
            Err(message) => {
                remaining.push(image_id.as_str());
                first_failure.get_or_insert_with(|| bounded_detail(&message));
            }
        }
    }
    if !remaining.is_empty() {
        let removed = images.len() - remaining.len();
        return Err(format!(
            "Local Assistant snapshots were only partially removed ({removed} of {}). Remaining: {}. First Docker failure: {}. Resolve the reported Docker condition for {assistant_id}, then rerun 'shimpz assistant unstage'.",
            images.len(),
            remaining.join(", "),
            first_failure.unwrap_or_else(|| "Docker refused the removal".into()),
        ));
    }
    Ok(images.len())
}

fn removal_success(assistant_id: &str, removed: usize) -> String {
    if removed == 0 {
        return format!("No Local Assistant snapshots are staged for {assistant_id}.");
    }
    format!(
        "Local Assistant snapshots removed.\nAssistant: {assistant_id}\nImages: {removed}\nNext: run 'shimpz assistant stage' to use it locally again."
    )
}

fn docker_failure_detail(result: &Output) -> String {
    let message = String::from_utf8_lossy(&result.stderr);
    message
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map_or_else(
            || "Docker refused the removal".into(),
            |line| bounded_detail(line.trim()),
        )
}

fn bounded_detail(value: &str) -> String {
    value.chars().take(MAX_FAILURE_DETAIL_CHARS).collect()
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
        .map_err(|_| "Docker could not execute the Local snapshot removal")?;
    if result.stdout.len() > MAX_DOCKER_OUTPUT_BYTES
        || result.stderr.len() > MAX_DOCKER_OUTPUT_BYTES
    {
        return Err("Docker returned excessive Local snapshot removal output".into());
    }
    Ok(result)
}

fn output_text(result: &Output) -> Result<&str, String> {
    std::str::from_utf8(&result.stdout)
        .map_err(|_| "Docker returned invalid Local snapshot removal output".into())
}

#[cfg(test)]
mod tests {
    use super::{canonical_image_ids, removal_success};

    fn image(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    #[test]
    fn accepts_a_canonical_inventory() {
        let first = image('a');
        let second = image('b');
        assert_eq!(
            canonical_image_ids(&format!("{second}\n{first}\n")),
            Ok(vec![first, second])
        );
        assert_eq!(canonical_image_ids(""), Ok(Vec::new()));
    }

    #[test]
    fn collapses_duplicate_references_before_bounded_removal() {
        let duplicate = image('a');
        assert_eq!(
            canonical_image_ids(&format!("{duplicate}\n{duplicate}\n")),
            Ok(vec![duplicate])
        );
        assert!(canonical_image_ids("latest\n").is_err());
    }

    #[test]
    fn renders_idempotent_absence_and_completed_removal_truthfully() {
        assert_eq!(
            removal_success("hello-world", 0),
            "No Local Assistant snapshots are staged for hello-world."
        );
        assert!(removal_success("hello-world", 2).contains("Images: 2"));
    }

    #[cfg(unix)]
    #[test]
    fn validates_before_removal_and_attempts_every_image_without_force() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        use super::{remove_images, staged_images, validate_images};

        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = directory.path().join("docker-proof");
        let log = directory.path().join("calls.log");
        let first = image('a');
        let second = image('b');
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$2\" = \"ls\" ]; then printf '%s\\n' \"$*\" > '{}'; printf '%s\\n%s\\n%s\\n' '{second}' '{first}' '{first}'; exit 0; fi\n\
             if [ \"$2\" = \"inspect\" ]; then printf '%s\\n%s\\n%s\\n' \"$5\" 'assistant-v3' 'proof-assistant'; exit 0; fi\n\
             if [ \"$2\" = \"rm\" ]; then printf '%s\\n' \"$*\" >> '{}'; [ \"$4\" != '{first}' ] && exit 0; printf '%s\\n' 'proof refusal' >&2; exit 1; fi\n\
             exit 2\n",
            log.display(),
            log.display()
        );
        fs::write(&executable, script).expect("fake Docker");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable fake Docker");

        let images = staged_images(&executable, "proof-assistant").expect("inventory");
        assert_eq!(images, vec![first, second]);
        validate_images(&executable, "proof-assistant", &images).expect("validation");
        let failure = remove_images(&executable, "proof-assistant", &images).unwrap_err();

        assert!(failure.contains("1 of 2"));
        assert!(failure.contains("proof refusal"));
        let calls = fs::read_to_string(log).expect("removal calls");
        let calls = calls.lines().collect::<Vec<_>>();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].contains("label=org.shimpz.local.stage=assistant-v3"));
        assert!(calls[0].contains("label=org.shimpz.assistant.id=proof-assistant"));
        assert!(
            calls[1..]
                .iter()
                .all(|call| call.contains("image rm --no-prune sha256:"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn removes_more_than_one_batch_and_confirms_final_absence() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        use super::{MAX_BATCH, remove_all};

        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = directory.path().join("docker-proof");
        let inventory = directory.path().join("inventory");
        let removed = directory.path().join("removed");
        let calls = directory.path().join("calls");
        let images = (0..=MAX_BATCH)
            .map(|index| format!("sha256:{index:064x}"))
            .collect::<Vec<_>>();
        fs::write(&inventory, format!("{}\n", images.join("\n"))).expect("inventory");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$2\" = \"ls\" ]; then printf 'ls\\n' >> '{}'; if [ -f '{}' ]; then grep -vxF -f '{}' '{}'; else cat '{}'; fi; exit 0; fi\n\
             if [ \"$2\" = \"inspect\" ]; then printf '%s\\n%s\\n%s\\n' \"$5\" 'assistant-v3' 'proof-assistant'; exit 0; fi\n\
             if [ \"$2\" = \"rm\" ]; then printf '%s\\n' \"$4\" >> '{}'; exit 0; fi\n\
             exit 2\n",
            calls.display(),
            removed.display(),
            removed.display(),
            inventory.display(),
            inventory.display(),
            removed.display(),
        );
        fs::write(&executable, script).expect("fake Docker");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable fake Docker");

        assert_eq!(
            remove_all(&executable, "proof-assistant"),
            Ok(MAX_BATCH + 1)
        );
        assert_eq!(
            fs::read_to_string(removed)
                .expect("removed images")
                .lines()
                .count(),
            MAX_BATCH + 1
        );
        assert_eq!(
            fs::read_to_string(calls)
                .expect("enumeration calls")
                .lines()
                .count(),
            3
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_docker_success_that_does_not_converge() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        use super::remove_all;

        let directory = tempfile::tempdir().expect("temporary directory");
        let executable = directory.path().join("docker-proof");
        let image = image('a');
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$2\" = \"ls\" ]; then printf '%s\\n' '{image}'; exit 0; fi\n\
             if [ \"$2\" = \"inspect\" ]; then printf '%s\\n%s\\n%s\\n' \"$5\" 'assistant-v3' 'proof-assistant'; exit 0; fi\n\
             if [ \"$2\" = \"rm\" ]; then exit 0; fi\n\
             exit 2\n"
        );
        fs::write(&executable, script).expect("fake Docker");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable fake Docker");

        let failure = remove_all(&executable, "proof-assistant").unwrap_err();

        assert!(failure.contains("without converging"));
    }

    #[test]
    fn local_snapshot_removal_has_no_account_space_or_force_authority() {
        let source = include_str!("unstage.rs");
        let implementation = source.split("#[cfg(test)]").next().unwrap();
        assert!(!implementation.contains("credentials"));
        assert!(!implementation.contains("ensure_authenticated"));
        assert!(!implementation.contains("lifecycle::"));
        assert!(!implementation.contains("--force"));
        assert!(!implementation.contains("image prune"));
    }
}

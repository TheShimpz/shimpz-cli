//! Create a minimal Python Assistant project.

use std::fs;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const DEFAULT_ICON_BASE64: &str = "iVBORw0KGgoAAAANSUhEUgAABAAAAAQAAQAAAABXZhYuAAAAlklEQVR42u3BAQEAAACCIP+vbkhAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADvBgQeAAEN3jhkAAAAAElFTkSuQmCC";

const GITIGNORE: &str = "\
.venv/
__pycache__/
*.pyc
";

const HELLO_LIBRARY: &str = "\
\"\"\"Build Hello World greetings.\"\"\"


def hello(name: str) -> str:
    return f\"Hello, {name}!\"
";

const HELLO_ACTION: &str = "\
\"\"\"Greet one person.\"\"\"

from typing import Annotated, TypedDict

from lib.hello import hello
from shimpz import action

Name = Annotated[str, \"Name to greet.\", {\"minLength\": 1, \"maxLength\": 80}]


class HelloWorldResult(TypedDict):
    message: str


@action()
async def run(name: Name) -> HelloWorldResult:
    return {\"message\": hello(name)}
";

const HELLO_TEST: &str = "\
import unittest

from lib.hello import hello


class HelloTests(unittest.TestCase):
    def test_greets_a_person(self) -> None:
        self.assertEqual(hello(\"World\"), \"Hello, World!\")


if __name__ == \"__main__\":
    unittest.main()
";

pub(crate) fn run(name: &str) -> Result<String, String> {
    let root = Path::new(name);
    if root.exists() {
        return Err(format!("{name} already exists"));
    }
    create(root, name)?;
    Ok(format!(
        "Created Python Assistant at {name}.\n\nNext:\n  cd {name}\n  shimpz check\n  shimpz test hello-world --input '{{\"name\":\"World\"}}'"
    ))
}

fn create(root: &Path, name: &str) -> Result<(), String> {
    let icon = BASE64
        .decode(DEFAULT_ICON_BASE64)
        .map_err(|_| "Assistant icon template is invalid".to_owned())?;
    fs::create_dir(root).map_err(|_| "Assistant directory cannot be created".to_owned())?;
    fs::create_dir(root.join("lib"))
        .and_then(|()| fs::create_dir(root.join("actions")))
        .and_then(|()| fs::create_dir(root.join("tests")))
        .and_then(|()| fs::write(root.join(".gitignore"), GITIGNORE))
        .and_then(|()| fs::write(root.join("shimpz.toml"), manifest(name)))
        .and_then(|()| fs::write(root.join("icon.png"), icon))
        .and_then(|()| fs::write(root.join("pyproject.toml"), pyproject(name)))
        .and_then(|()| fs::write(root.join("README.md"), readme(name)))
        .and_then(|()| fs::write(root.join("lib/hello.py"), HELLO_LIBRARY))
        .and_then(|()| fs::write(root.join("actions/hello_world.py"), HELLO_ACTION))
        .and_then(|()| fs::write(root.join("tests/test_hello.py"), HELLO_TEST))
        .map_err(|_| "Assistant files cannot be created".to_owned())
}

fn manifest(name: &str) -> String {
    let display_name = display_name(name);
    format!(
        "\
[shimpz]
spec = 1
id = \"{name}\"
version = \"0.1.0\"
name = \"{display_name}\"
summary = \"A Hello World Assistant for Shimpz.\"
creators = [\"@your-github-username\"]
github = \"https://github.com/your-github-username/{name}\"
genesis = \"\"\"
Use this Assistant to greet people.

Call hello-world with the name of the person to greet.
\"\"\"

[network]
allowed_hosts = []
"
    )
}

fn pyproject(name: &str) -> String {
    format!(
        "\
[project]
name = \"{name}\"
version = \"0.1.0\"
description = \"A Hello World Assistant for Shimpz\"
requires-python = \">=3.14\"
dependencies = [
  \"shimpz==0.3.0\",
]

[tool.ruff]
target-version = \"py314\"
line-length = 120

[tool.ruff.lint]
select = [
  \"F\", \"E4\", \"E7\", \"E9\", \"W\", \"I\", \"UP\", \"B\", \"S\", \"ASYNC\",
  \"C4\", \"SIM\", \"PTH\", \"PIE\", \"PERF\", \"FURB\", \"RUF\", \"BLE\",
]
ignore = [\"S311\", \"RUF001\", \"RUF002\", \"RUF003\"]

[tool.ruff.lint.per-file-ignores]
\"tests/**\" = [\"S101\", \"S105\", \"S108\", \"S310\"]
"
    )
}

fn readme(name: &str) -> String {
    let display_name = display_name(name);
    format!(
        "\
# {display_name}

A minimal Hello World Assistant for Shimpz.

Each file in `actions/` is one Action. Shared code lives in `lib/hello.py`. The Shimpz CLI manages
Python and the SDK, generates the machine contract in memory, and runs Actions without Docker.

## Local checks

```console
shimpz check
shimpz test hello-world --input '{{\"name\":\"World\"}}'
```
"
    )
}

fn display_name(name: &str) -> String {
    name.split('-')
        .map(|word| {
            let mut characters = word.chars();
            match characters.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory {
        path: std::path::PathBuf,
    }

    impl TemporaryDirectory {
        fn new() -> Self {
            let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "shimpz-new-assistant-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    #[test]
    fn creates_the_minimal_python_assistant_structure() {
        let temporary = TemporaryDirectory::new();
        let root = temporary.path.join("hello-assistant");

        create(&root, "hello-assistant").unwrap();

        let files = walk_files(&root);
        assert_eq!(
            files,
            BTreeSet::from([
                ".gitignore".into(),
                "README.md".into(),
                "icon.png".into(),
                "lib/hello.py".into(),
                "actions/hello_world.py".into(),
                "pyproject.toml".into(),
                "shimpz.toml".into(),
                "tests/test_hello.py".into(),
            ])
        );
        let manifest = fs::read_to_string(root.join("shimpz.toml")).unwrap();
        assert!(manifest.contains("id = \"hello-assistant\""));
        assert!(manifest.contains("name = \"Hello Assistant\""));
        assert!(
            fs::read(root.join("icon.png"))
                .unwrap()
                .starts_with(b"\x89PNG\r\n\x1a\n")
        );
        crate::source_package::build(&root).expect("publishable generated Assistant");
        assert!(
            fs::read_to_string(root.join("pyproject.toml"))
                .unwrap()
                .contains("\"shimpz==0.3.0\"")
        );
        assert!(
            fs::read_to_string(root.join("actions/hello_world.py"))
                .unwrap()
                .contains("return {\"message\": hello(name)}")
        );
    }

    #[test]
    fn refuses_to_replace_an_existing_target() {
        let temporary = TemporaryDirectory::new();
        let original = temporary.path.join("hello");
        fs::write(&original, "keep me").unwrap();

        let error = run(original.to_str().unwrap()).unwrap_err();

        assert!(error.ends_with("already exists"));
        assert_eq!(fs::read_to_string(original).unwrap(), "keep me");
    }

    fn walk_files(root: &Path) -> BTreeSet<String> {
        let mut directories = vec![root.to_owned()];
        let mut files = BTreeSet::new();
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    directories.push(entry.path());
                } else {
                    files.insert(
                        entry
                            .path()
                            .strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        files
    }
}

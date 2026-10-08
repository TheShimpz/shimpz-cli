//! The one Assistant identifier grammar of the Developers published-Assistant protocol, with its two bounds.
//!
//! An Assistant id is the protocol's `assistantIdentifier`; an Action, Integration, or Stored Input id is its
//! `identifier`. Both are lowercase ASCII words joined by single hyphens, as in `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`.

const MAX_ASSISTANT_ID: usize = 40;
const MAX_IDENTIFIER: usize = 64;
/// Assistant ids the protocol reserves for Local Space names.
const RESERVED_ASSISTANT_IDS: [&str; 3] =
    ["postgres", "assistant-egress", "shimpz-assistant-egress"];

/// One to 40 bytes of the identifier grammar that are not a reserved Local Space name.
pub(crate) fn assistant_id(value: &str) -> bool {
    bounded(value, MAX_ASSISTANT_ID) && !RESERVED_ASSISTANT_IDS.contains(&value)
}

/// One to 64 bytes of the identifier grammar: an Assistant-declared Action, Integration, or Stored Input id.
pub(crate) fn declared(value: &str) -> bool {
    bounded(value, MAX_IDENTIFIER)
}

fn bounded(value: &str, maximum: usize) -> bool {
    let bytes = value.as_bytes();
    (1..=maximum).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

#[cfg(test)]
mod tests {
    use super::{assistant_id, declared};

    /// Values neither bound admits; the protocol vectors of both Developers and Team are among them.
    const REFUSED: [&str; 17] = [
        "",
        "Hello",
        "Api-token",
        "hello_world",
        "api.token",
        "hello--world",
        "a--b",
        "-a",
        "a-",
        "1a",
        "a b",
        " a",
        "a\n",
        "hello-world\n",
        "h\u{e9}llo",
        "a\u{0}",
        "a/b",
    ];

    #[test]
    fn assistant_ids_admit_forty_bytes_and_refuse_reserved_names() {
        for admitted in ["a", "a-b", "hello-world", "a1-b2", &"a".repeat(40)] {
            assert!(assistant_id(admitted), "{admitted}");
        }
        for refused in REFUSED.iter().copied().chain([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "postgres",
            "assistant-egress",
            "shimpz-assistant-egress",
        ]) {
            assert!(!assistant_id(refused), "{refused:?}");
        }
        assert_eq!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".len(), 41);
    }

    #[test]
    fn declared_ids_admit_sixty_four_bytes_without_reserved_names() {
        for admitted in [
            "a",
            "a-b",
            "api-token",
            "postgres",
            "assistant-egress",
            "shimpz-assistant-egress",
            &"a".repeat(41),
            &"a".repeat(64),
        ] {
            assert!(declared(admitted), "{admitted}");
        }
        for refused in REFUSED
            .iter()
            .copied()
            .chain(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
        {
            assert!(!declared(refused), "{refused:?}");
        }
        assert_eq!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".len(),
            65
        );
    }
}

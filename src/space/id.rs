//! The one Local Space identity grammar: `space-` followed by 24 lowercase hexadecimal characters.

use crate::digest;

const PREFIX: &str = "space-";
const SUFFIX_HEX: usize = 24;

/// An exact Local Space identity.
pub(crate) fn valid(value: &str) -> bool {
    value.strip_prefix(PREFIX).is_some_and(valid_suffix)
}

/// The random part of a Space identity, as names derived from it carry it.
pub(crate) fn valid_suffix(value: &str) -> bool {
    digest::is_lower_hex(value, SUFFIX_HEX)
}

#[cfg(test)]
mod tests {
    use super::{valid, valid_suffix};

    #[test]
    fn admits_only_exact_space_ids() {
        assert!(valid("space-0123456789abcdef01234567"));
        assert!(valid_suffix("0123456789abcdef01234567"));
        for invalid in [
            "0123456789abcdef01234567",
            "space-0123456789abcdef0123456",
            "space-0123456789abcdef012345678",
            "space-0123456789ABCDEF01234567",
            "space-0123456789abcdef0123456g",
            "Space-0123456789abcdef01234567",
        ] {
            assert!(!valid(invalid), "{invalid}");
        }
    }
}

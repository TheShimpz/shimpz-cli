//! The one Team id grammar the CLI admits from Local resource labels.

/// One to 40 bytes of lowercase ASCII letters, digits, or underscores, as the Team protocol defines a Team id.
pub(crate) fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::valid;

    #[test]
    fn admits_only_the_closed_team_id_grammar() {
        for admitted in ["team_1", "a", &"a".repeat(40)] {
            assert!(valid(admitted), "{admitted}");
        }
        for refused in ["", "Team", "team-1", "team 1", "t\u{e9}am", &"a".repeat(41)] {
            assert!(!valid(refused), "{refused}");
        }
    }
}

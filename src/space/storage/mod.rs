//! Local data-at-rest admission.

pub(crate) mod evidence;
#[cfg(unix)]
pub(crate) mod linux;
pub(crate) mod managed;

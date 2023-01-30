pub mod backend;
pub mod ext;

use serde::{Deserialize, Serialize};
use trussed::types::Bytes;

// TODO: reset codes?
// TODO: reset other PIN

// TODO: reconsider
pub const MAX_PIN_LENGTH: usize = 32;
pub type Pin = Bytes<MAX_PIN_LENGTH>;

// TODO: add custom
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum PinType {
    User,
    Admin,
}

#[derive(Clone, Debug, Default)]
pub struct PinOptions {
    /// Determines whether the PIN length can be accessed using the [`leak_pin_length`][] syscall.
    ///
    /// [`leak_pin_length`]: `ext::AuthClient::leak_pin_length`
    pub leak_length: bool,
}

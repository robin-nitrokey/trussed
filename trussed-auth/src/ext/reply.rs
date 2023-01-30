use serde::{Deserialize, Serialize};
use trussed::error::{Error, Result};

use super::AuthReply;

#[derive(Debug, Deserialize, Serialize)]
pub struct Authenticate;

impl From<Authenticate> for AuthReply {
    fn from(reply: Authenticate) -> Self {
        Self::Authenticate(reply)
    }
}

impl TryFrom<AuthReply> for Authenticate {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::Authenticate(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Deauthenticate;

impl From<Deauthenticate> for AuthReply {
    fn from(reply: Deauthenticate) -> Self {
        Self::Deauthenticate(reply)
    }
}

impl TryFrom<AuthReply> for Deauthenticate {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::Deauthenticate(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckPin;

impl From<CheckPin> for AuthReply {
    fn from(reply: CheckPin) -> Self {
        Self::CheckPin(reply)
    }
}

impl TryFrom<AuthReply> for CheckPin {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::CheckPin(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetPin;

impl From<SetPin> for AuthReply {
    fn from(reply: SetPin) -> Self {
        Self::SetPin(reply)
    }
}

impl TryFrom<AuthReply> for SetPin {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::SetPin(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PinRetries {
    pub admin: u8,
    pub user: u8,
}

impl From<PinRetries> for AuthReply {
    fn from(reply: PinRetries) -> Self {
        Self::PinRetries(reply)
    }
}

impl TryFrom<AuthReply> for PinRetries {
    type Error = Error;

    fn try_from(reply: AuthReply) -> Result<Self> {
        match reply {
            AuthReply::PinRetries(reply) => Ok(reply),
            _ => Err(Error::InternalError),
        }
    }
}

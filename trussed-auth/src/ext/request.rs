use serde::{Deserialize, Serialize};

use super::AuthRequest;
use crate::{Pin, PinType};

#[derive(Debug, Deserialize, Serialize)]
pub struct Authenticate {
    pub ty: PinType,
    pub pin: Pin,
}

impl From<Authenticate> for AuthRequest {
    fn from(request: Authenticate) -> Self {
        Self::Authenticate(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Deauthenticate;

impl From<Deauthenticate> for AuthRequest {
    fn from(request: Deauthenticate) -> Self {
        Self::Deauthenticate(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckPin {
    pub ty: PinType,
    pub pin: Pin,
}

impl From<CheckPin> for AuthRequest {
    fn from(request: CheckPin) -> Self {
        Self::CheckPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetPin {
    pub ty: PinType,
    pub pin: Pin,
}

impl From<SetPin> for AuthRequest {
    fn from(request: SetPin) -> Self {
        Self::SetPin(request)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PinRetries;

impl From<PinRetries> for AuthRequest {
    fn from(request: PinRetries) -> Self {
        Self::PinRetries(request)
    }
}

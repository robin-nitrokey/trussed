pub mod reply;
pub mod request;

use serde::{Deserialize, Serialize};
use trussed::ext::{Extension, ExtensionClient, ExtensionResult};

use crate::{Pin, PinType};

pub type AuthResult<'a, R, C> = ExtensionResult<'a, AuthExtension, R, C>;

pub struct AuthExtension;

impl Extension for AuthExtension {
    type Request = AuthRequest;
    type Reply = AuthReply;
}

#[derive(Debug, Deserialize, Serialize)]
pub enum AuthRequest {
    Authenticate(request::Authenticate),
    Deauthenticate(request::Deauthenticate),
    CheckPin(request::CheckPin),
    SetPin(request::SetPin),
    PinRetries(request::PinRetries),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum AuthReply {
    Authenticate(reply::Authenticate),
    Deauthenticate(reply::Deauthenticate),
    CheckPin(reply::CheckPin),
    SetPin(reply::SetPin),
    PinRetries(reply::PinRetries),
}

pub trait AuthClient: ExtensionClient<AuthExtension> {
    fn authenticate(&mut self, ty: PinType, pin: Pin) -> AuthResult<'_, reply::Authenticate, Self> {
        self.extension(request::Authenticate { ty, pin })
    }

    fn deauthenticate(&mut self) -> AuthResult<'_, reply::Deauthenticate, Self> {
        self.extension(request::Deauthenticate)
    }

    fn check_pin(&mut self, ty: PinType, pin: Pin) -> AuthResult<'_, reply::CheckPin, Self> {
        // TODO: Do we need this one?  Should it return an an error or false if the pin is wrong?
        self.extension(request::CheckPin { ty, pin })
    }

    fn set_pin(&mut self, ty: PinType, pin: Pin) -> AuthResult<'_, reply::SetPin, Self> {
        self.extension(request::SetPin { ty, pin })
    }

    fn pin_retries(&mut self) -> AuthResult<'_, reply::PinRetries, Self> {
        self.extension(request::PinRetries)
    }
}

impl<C: ExtensionClient<AuthExtension>> AuthClient for C {}

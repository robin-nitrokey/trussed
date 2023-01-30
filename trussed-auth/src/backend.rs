mod state;

use trussed::{
    backend::Backend,
    error::Result,
    ext::ExtensionImpl,
    platform::Platform,
    service::ServiceResources,
    store::filestore::{ClientFilestore, Filestore},
    types::ClientContext,
};

use crate::{
    ext::{reply, AuthExtension, AuthReply, AuthRequest},
    PinType,
};

use state::State;

// TODO: errors
// TODO: hash pins?

pub struct AuthBackend;

impl<P: Platform> Backend<P> for AuthBackend {
    type Context = Context;
}

impl<P: Platform> ExtensionImpl<AuthExtension, P> for AuthBackend {
    fn extension_request(
        &mut self,
        client_ctx: &mut ClientContext,
        ctx: &mut Context,
        request: &AuthRequest,
        resources: &mut ServiceResources<P>,
    ) -> Result<AuthReply> {
        let mut fs = ClientFilestore::new(client_ctx.path.clone(), resources.platform.store());
        let state = ctx.state(&mut fs)?;
        match request {
            AuthRequest::Authenticate(request) => {
                // TODO: what to do if we are already authenticated with request.ty?
                state.write(&mut fs, |state| {
                    state.authenticate(request.ty, &request.pin)
                })?;
                Ok(reply::Authenticate.into())
            }
            AuthRequest::Deauthenticate(_) => {
                state.deauthenticate();
                Ok(reply::Deauthenticate.into())
            }
            AuthRequest::CheckPin(request) => {
                state.write(&mut fs, |state| state.check_pin(request.ty, &request.pin))?;
                Ok(reply::CheckPin.into())
            }
            AuthRequest::SetPin(request) => {
                state.write(&mut fs, |state| {
                    state.set_pin(request.ty, &request.pin);
                    Ok(())
                })?;
                Ok(reply::SetPin.into())
            }
            AuthRequest::PinRetries(_) => {
                let retries = state.pin_retries();
                let admin = *retries.get(PinType::Admin);
                let user = *retries.get(PinType::User);
                Ok(reply::PinRetries { admin, user }.into())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Context {
    state: Option<State>,
}

impl Context {
    pub fn state<S: Filestore>(&mut self, fs: &mut S) -> Result<&mut State> {
        // A nicer if let implementation does not work due to
        // https://github.com/rust-lang/rust/issues/47680
        if self.state.is_none() {
            self.state = Some(State::load(fs)?);
        }
        // We just set state to Some so this cannot panic
        Ok(self.state.as_mut().unwrap())
    }
}

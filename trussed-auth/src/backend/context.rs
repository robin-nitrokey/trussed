use trussed::{error::{Error, Result}, store::filestore::Filestore};

use crate::{Pin, PinType};

const DEFAULT_RETRIES: u8 = 3;
const DEFAULT_USER_PIN: &[u8] = b"123456";
const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

const STATE_PATH: &str = "ext/auth/state";

#[derive(Debug, Default)]
pub struct Context {
    authentication: Option<PinType>,
    state: Option<State>,
}

impl Context {
    pub fn authentication(&self) -> Option<PinType> {
        self.authentication
    }

    pub fn authenticate(&mut self, ty: PinType, pin: &Pin) -> Result<()> {
        self.check_pin(ty, pin)?;
        self.authentication = Some(ty);
        Ok(())
    }

    pub fn deauthenticate(&mut self) {
        self.authentication = None;
    }

    pub fn check_pin(&mut self, ty: PinType, pin: &Pin) -> Result<()> {
        if self.state().retries.is_blocked(ty) {
            return Err(Error::InternalError);
        }
        self.with_state(|state| {
            if state.pins.check(ty, pin) {
                state.retries.reset(ty);
                Ok(())
            } else {
                state.retries.decrement(ty);
                Err(Error::InternalError)
            }
        })
    }

    pub fn set_pin(&mut self, ty: PinType, pin: &Pin) -> Result<()> {
        if self.authentication == Some(ty) {
            self.with_state(|state| state.pins.set(ty, pin))
        } else {
            Err(Error::InternalError)
        }
    }

    pub fn state(&mut self) -> &State {
        if let Some(state) = &self.state {
            state
        } else {
            unimplemented!();
        }
    }

    fn with_state<T, F: FnOnce(&mut State) -> Result<T>>(&mut self, f: F) -> Result<T> {
        // TODO: save state after calling f
        if let Some(state) = &mut self.state {
            let result = f(state);
            unimplemented!();
        } else {
            unimplemented!();
        }
    }
}

#[derive(Debug, Default)]
pub struct State {
    pins: Pins,
    retries: Retries,
}

impl State {
    fn load<F: Filestore>(fs: &mut F) -> Result<Self> {
        unimplemented!();
    }

    fn save<F: Filestore>(&self, fs: &mut F) -> Result<()> {
        unimplemented!();
    }

    pub fn retries(&self) -> &Retries {
        &self.retries
    }
}

#[derive(Debug)]
struct Pins {
    user: Pin,
    admin: Pin,
}

impl Pins {
    fn get(&self, ty: PinType) -> &Pin {
        match ty {
            PinType::User => &self.user,
            PinType::Admin => &self.admin,
        }
    }

    fn get_mut(&mut self, ty: PinType) -> &mut Pin {
        match ty {
            PinType::User => &mut self.user,
            PinType::Admin => &mut self.admin,
        }
    }

    fn check(&self, ty: PinType, pin: &Pin) -> bool {
        // TODO: secure comparison
        self.get(ty) == pin
    }

    fn reset(&mut self, ty: PinType) {
        let default = match ty {
            PinType::User => DEFAULT_USER_PIN,
            PinType::Admin => DEFAULT_ADMIN_PIN,
        };
        let pin = self.get_mut(ty);
        pin.clear();
        pin.extend_from_slice(default).unwrap();
    }

    fn set(&mut self, ty: PinType, new: &Pin) -> Result<()> {
        // TODO: check pin length
        let pin = self.get_mut(ty);
        pin.clear();
        pin.extend_from_slice(new).unwrap();
        Ok(())
    }
}

impl Default for Pins {
    fn default() -> Self {
        let user = Pin::from_slice(DEFAULT_USER_PIN).unwrap();
        let admin = Pin::from_slice(DEFAULT_ADMIN_PIN).unwrap();
        Self { user, admin }
    }
}

#[derive(Debug)]
pub struct Retries {
    user: u8,
    admin: u8,
}

impl Retries {
    pub fn get(&self, ty: PinType) -> u8 {
        match ty {
            PinType::User => self.user,
            PinType::Admin => self.admin,
        }
    }

    fn get_mut(&mut self, ty: PinType) -> &mut u8 {
        match ty {
            PinType::User => &mut self.user,
            PinType::Admin => &mut self.admin,
        }
    }

    fn is_blocked(&self, ty: PinType) -> bool {
        self.get(ty) == 0
    }

    fn reset(&mut self, ty: PinType) {
        *self.get_mut(ty) = DEFAULT_RETRIES;
    }

    fn decrement(&mut self, ty: PinType) {
        let retries = self.get_mut(ty);
        *retries = retries.saturating_sub(1);
    }
}

impl Default for Retries {
    fn default() -> Self {
        Self {
            user: DEFAULT_RETRIES,
            admin: DEFAULT_RETRIES,
        }
    }
}

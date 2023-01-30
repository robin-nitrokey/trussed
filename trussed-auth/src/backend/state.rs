use core::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use trussed::{
    cbor_deserialize, cbor_serialize_bytes,
    error::{Error, Result},
    store::filestore::Filestore,
    types::{Bytes, Location},
};

use crate::{Pin, PinType};

const PATH: &str = "auth/state";
const LOCATION: Location = Location::Internal;
const SIZE: usize = 1024; // TODO: choose

const DEFAULT_RETRIES: u8 = 3;
const DEFAULT_USER_PIN: &[u8] = b"123456";
const DEFAULT_ADMIN_PIN: &[u8] = b"12345678";

#[derive(Debug, Default)]
pub struct State {
    persistent: Persistent,
    runtime: Runtime,
}

impl State {
    pub fn load<F: Filestore>(fs: &mut F) -> Result<Self> {
        Persistent::read(fs).map(|persistent| Self {
            persistent,
            runtime: Default::default(),
        })
    }

    pub fn authentication(&self) -> Option<PinType> {
        self.runtime.authentication
    }

    pub fn deauthenticate(&mut self) {
        self.runtime.authentication = None;
    }

    pub fn pin_retries(&self) -> PinData<u8> {
        self.persistent.retries
    }

    pub fn write<'a, S, F, R>(&'a mut self, fs: &mut S, f: F) -> Result<R>
    where
        S: Filestore,
        F: Fn(&mut MutableState<'a>) -> Result<R>,
    {
        let mut state = MutableState::new(self);
        let result = f(&mut state);
        if state.changed {
            state.persistent.write(fs)?;
        }
        result
    }
}

#[derive(Debug)]
pub struct MutableState<'a> {
    state: &'a mut State,
    changed: bool,
}

impl<'a> MutableState<'a> {
    fn new(state: &'a mut State) -> Self {
        Self {
            state,
            changed: false,
        }
    }
}

impl MutableState<'_> {
    pub fn authenticate(&mut self, ty: PinType, pin: &Pin) -> Result<()> {
        self.check_pin(ty, pin)?;
        self.runtime.authentication = Some(ty);
        Ok(())
    }

    pub fn check_pin(&mut self, ty: PinType, pin: &Pin) -> Result<()> {
        if self.state.persistent.is_blocked(ty) {
            return Err(Error::InternalError);
        }
        if self.persistent.check_pin(ty, pin) {
            if self.persistent.reset_retries(ty) {
                self.changed = true;
            }
            Ok(())
        } else {
            self.persistent.decrement_retries(ty);
            self.changed = true;
            Err(Error::InternalError)
        }
    }

    pub fn set_pin(&mut self, ty: PinType, pin: &Pin) {
        self.persistent.set_pin(ty, pin);
        self.changed = true;
    }
}

impl Deref for MutableState<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        self.state
    }
}

impl DerefMut for MutableState<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
struct Persistent {
    pins: PinData<Pin>,
    retries: PinData<u8>,
}

impl Persistent {
    fn read<S: Filestore>(fs: &mut S) -> Result<Self> {
        if let Ok(data) = fs.read::<SIZE>(&PATH.into(), LOCATION) {
            cbor_deserialize(&data).map_err(|_| Error::InternalError)
        } else {
            Ok(Default::default())
        }
    }

    fn write<S: Filestore>(&mut self, fs: &mut S) -> Result<()> {
        let data: Bytes<SIZE> = cbor_serialize_bytes(self).map_err(|_| Error::InternalError)?;
        fs.write(&PATH.into(), LOCATION, &data)
    }

    fn is_blocked(&self, ty: PinType) -> bool {
        *self.retries.get(ty) == 0
    }

    fn check_pin(&self, ty: PinType, pin: &Pin) -> bool {
        // TODO: secure comparison
        self.pins.get(ty) == pin
    }

    fn set_pin(&mut self, ty: PinType, new: &Pin) {
        // TODO: check pin length
        let old = self.pins.get_mut(ty);
        old.clear();
        // We can unwrap here because pin and old and new have the same capacity and we just
        // cleared old.
        old.extend_from_slice(new).unwrap();
    }

    fn reset_retries(&mut self, ty: PinType) -> bool {
        let retries = self.retries.get_mut(ty);
        if *retries == DEFAULT_RETRIES {
            false
        } else {
            *self.retries.get_mut(ty) = DEFAULT_RETRIES;
            true
        }
    }

    fn decrement_retries(&mut self, ty: PinType) {
        let retries = self.retries.get_mut(ty);
        *retries = retries.saturating_sub(1);
    }
}

impl Default for Persistent {
    fn default() -> Self {
        Self {
            pins: PinData {
                user: Pin::from_slice(DEFAULT_USER_PIN).unwrap(),
                admin: Pin::from_slice(DEFAULT_ADMIN_PIN).unwrap(),
            },
            retries: PinData {
                user: DEFAULT_RETRIES,
                admin: DEFAULT_RETRIES,
            },
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PinData<T> {
    user: T,
    admin: T,
}

impl<T> PinData<T> {
    pub fn get(&self, ty: PinType) -> &T {
        match ty {
            PinType::Admin => &self.admin,
            PinType::User => &self.user,
        }
    }

    pub fn get_mut(&mut self, ty: PinType) -> &mut T {
        match ty {
            PinType::Admin => &mut self.admin,
            PinType::User => &mut self.user,
        }
    }
}

#[derive(Debug, Default)]
struct Runtime {
    authentication: Option<PinType>,
}

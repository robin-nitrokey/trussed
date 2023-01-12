//! Trussed platform implemented in software with RAM storage **FOR TESTING ONLY**
//!
//! The random number generator in this module uses a
//! constant seed for test reproducability and by consequence is **not secure**

mod store;
mod ui;

use std::{
    marker::PhantomData,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng as _;

use crate::{
    api::{Reply, Request},
    error::Error,
    pipe::{TrussedInterchange, CLIENT_COUNT},
    platform,
    service::Service,
    types::Backends,
    ClientImplementation,
};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

interchange::interchange! {
    SimpleInterchange: (Request<()>, Result<Reply, Error>, CLIENT_COUNT)
}

pub type Client<S> = ClientImplementation<SimpleInterchange, Service<Platform<S>, ()>>;

// We need this mutex to make sure that:
// - the interchange is not used concurrently
// - the Store is not used concurrently
static MUTEX: Mutex<()> = Mutex::new(());

pub fn with_platform<S, R, F>(store: S, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Platform<S>) -> R,
{
    f(Platform::new(store))
}

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Client<S>) -> R,
{
    Platform::new(store).run_client(client_id, (), f)
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce(Client<Filesystem>) -> R,
{
    Platform::new(Filesystem::new(internal)).run_client(client_id, (), f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram>) -> R,
{
    Platform::new(Ram::default()).run_client(client_id, (), f)
}

pub struct Platform<S: StoreProvider, I = SimpleInterchange, B = ()> {
    rng: ChaCha8Rng,
    _store: S,
    ui: UserInterface,
    _guard: MutexGuard<'static, ()>,
    _marker: PhantomData<(I, B)>,
}

impl<S: StoreProvider, I: TrussedInterchange<B>, B: 'static + PartialEq> Platform<S, I, B> {
    pub fn new(store: S) -> Self {
        let _guard = MUTEX.lock().unwrap_or_else(|err| err.into_inner());
        unsafe {
            I::reset_claims();
            store.reset();
        }
        // causing a regression again
        // let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
        Self {
            rng: ChaCha8Rng::from_seed([42u8; 32]),
            _store: store,
            ui: UserInterface::new(),
            _guard,
            _marker: Default::default(),
        }
    }

    pub fn run_client<R, Bs: Backends<Self>>(
        self,
        client_id: &str,
        backends: Bs,
        test: impl FnOnce(ClientImplementation<I, Service<Self, Bs>>) -> R,
    ) -> R {
        let service = Service::new(self, backends);
        let client = service.try_into_new_client(client_id).unwrap();
        test(client)
    }
}

unsafe impl<S: StoreProvider, I: TrussedInterchange<B>, B: 'static + PartialEq> platform::Platform
    for Platform<S, I, B>
{
    type B = B;
    type I = I;
    type R = ChaCha8Rng;
    type S = S::Store;
    type UI = UserInterface;

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        unsafe { S::store() }
    }
}

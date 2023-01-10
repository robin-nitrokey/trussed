//! Trussed platform implemented in software with RAM storage **FOR TESTING ONLY**
//!
//! The random number generator in this module uses a
//! constant seed for test reproducability and by consequence is **not secure**

mod store;
mod ui;

use std::{
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use chacha20::ChaCha8Rng;
use rand_core::SeedableRng as _;

use crate::{
    api::{Reply, Request},
    error::Error,
    pipe::{TrussedInterchange, CLIENT_COUNT},
    platform,
    service::Service,
    types::ServiceBackend,
    ClientImplementation, Interchange as _,
};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

interchange::interchange! {
    SimpleInterchange: (Request<()>, Result<Reply, Error>, CLIENT_COUNT)
}

pub type Client<S> = ClientImplementation<SimpleInterchange, Service<Platform<S>>>;

// We need this mutex to make sure that:
// - the interchange is not used concurrently
// - the Store is not used concurrently
static MUTEX: Mutex<()> = Mutex::new(());

pub fn with_platform<S, R, F>(store: S, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Platform<S>) -> R,
{
    f(Platform::new(store, ()))
}

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Client<S>) -> R,
{
    Platform::new(store, ()).run_client(client_id, f)
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce(Client<Filesystem>) -> R,
{
    Platform::new(Filesystem::new(internal), ()).run_client(client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram>) -> R,
{
    Platform::new(Ram::default(), ()).run_client(client_id, f)
}

pub struct Platform<S: StoreProvider, B = ()> {
    rng: ChaCha8Rng,
    _store: S,
    ui: UserInterface,
    backends: B,
    _guard: MutexGuard<'static, ()>,
}

impl<S: StoreProvider, B: Backends> Platform<S, B> {
    pub fn new(store: S, backends: B) -> Self {
        let _guard = MUTEX.lock().unwrap_or_else(|err| err.into_inner());
        unsafe {
            B::I::reset_claims();
            store.reset();
        }
        // causing a regression again
        // let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
        Self {
            rng: ChaCha8Rng::from_seed([42u8; 32]),
            _store: store,
            ui: UserInterface::new(),
            backends,
            _guard,
        }
    }

    pub fn run_client<R>(
        self,
        client_id: &str,
        test: impl FnOnce(ClientImplementation<B::I, Service<Self>>) -> R,
    ) -> R {
        let service = Service::new(self);
        let client = service.try_into_new_client(client_id).unwrap();
        test(client)
    }
}

unsafe impl<S: StoreProvider, B: Backends> platform::Platform for Platform<S, B> {
    type B = B::B;
    type I = B::I;
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

    fn backend(&mut self, backend: Self::B) -> Option<&mut dyn ServiceBackend<Self::B>> {
        self.backends.select(backend)
    }
}

pub trait Backends {
    type B: Clone + PartialEq;
    type I: TrussedInterchange<Self::B>;

    fn select(&mut self, backend: Self::B) -> Option<&mut dyn ServiceBackend<Self::B>>;
}

impl Backends for () {
    type B = ();
    type I = SimpleInterchange;

    fn select(&mut self, _backend: Self::B) -> Option<&mut dyn ServiceBackend<Self::B>> {
        None
    }
}

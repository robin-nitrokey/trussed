#![cfg(feature = "virt")]

use heapless::Vec;
use trussed::{
    api::{reply::ReadFile, Reply, Request},
    client::{FilesystemClient as _, PollClient as _},
    error::Error,
    pipe::CLIENT_COUNT,
    service::Service,
    types::{ClientContext, Location, Message, PathBuf, ServiceBackend, ServiceBackends},
    virt::{self, Platform, Ram},
    ClientImplementation,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Backend {
    Test,
}

#[derive(Default)]
struct Backends {
    test: TestBackend,
}

impl virt::Backends for Backends {
    type B = Backend;
    type I = Interchange;

    fn select(&mut self, backend: Self::B) -> Option<&mut dyn ServiceBackend<Self::B>> {
        match backend {
            Self::B::Test => Some(&mut self.test),
        }
    }
}

#[derive(Default)]
struct TestBackend;

impl<B> ServiceBackend<B> for TestBackend {
    fn reply_to(
        &mut self,
        _client_id: &mut ClientContext<B>,
        request: &Request<B>,
    ) -> Result<Reply, Error> {
        match request {
            Request::ReadFile(_) => {
                let mut data = Message::new();
                data.push(0xff).unwrap();
                Ok(Reply::ReadFile(ReadFile { data }))
            }
            _ => Err(Error::RequestNotAvailable),
        }
    }
}

interchange::interchange! {
    Interchange: (Request<Backend>, Result<Reply, Error>, CLIENT_COUNT)
}

fn run<F: FnOnce(&mut ClientImplementation<Interchange, Service<Platform<Ram, Backends>>>)>(f: F) {
    Platform::new(Ram::default(), Backends::default())
        .run_client("test", |mut client| f(&mut client))
}

#[test]
fn override_syscall() {
    run(|client| {
        let path = PathBuf::from("test");
        assert!(trussed::try_syscall!(client.read_file(Location::Internal, path.clone())).is_err());

        let mut backends = Vec::new();
        backends
            .push(ServiceBackends::Custom(Backend::Test))
            .unwrap();
        backends.push(ServiceBackends::Software).unwrap();
        trussed::syscall!(client.set_service_backends(backends));

        assert_eq!(
            trussed::syscall!(client.read_file(Location::Internal, path)).data,
            &[0xff]
        );
    })
}

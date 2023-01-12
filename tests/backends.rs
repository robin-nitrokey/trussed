#![cfg(feature = "virt")]

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

const BACKENDS_TEST: &[ServiceBackends<Backend>] = &[
    ServiceBackends::Custom(Backend::Test),
    ServiceBackends::Software,
];

#[derive(Clone, Debug, PartialEq)]
pub enum Backend {
    Test,
}

#[derive(Default)]
struct Backends {
    test: TestBackend,
}

impl virt::Backends for Backends {
    type Backend = Backend;
    type Interchange = Interchange;

    fn select(
        &mut self,
        backend: &Self::Backend,
    ) -> Option<&mut dyn ServiceBackend<Self::Backend>> {
        match backend {
            Backend::Test => Some(&mut self.test),
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

fn run<F>(f: F)
where
    F: FnOnce(&mut ClientImplementation<Backend, Interchange, Service<Platform<Ram, Backends>>>),
{
    Platform::new(Ram::default(), Backends::default())
        .run_client("test", |mut client| f(&mut client))
}

#[test]
fn override_syscall() {
    run(|client| {
        let path = PathBuf::from("test");
        assert!(trussed::try_syscall!(client.read_file(Location::Internal, path.clone())).is_err());

        trussed::syscall!(client.set_service_backends(BACKENDS_TEST));

        assert_eq!(
            trussed::syscall!(client.read_file(Location::Internal, path)).data,
            &[0xff]
        );
    })
}

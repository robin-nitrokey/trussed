use crate::{
    api::{reply, request, Reply, Request},
    error::Error,
    platform::Platform,
    service::ServiceResources,
    types::{ClientContext, Context},
};

pub enum BackendId<C> {
    Software,
    Custom(C),
}

pub trait Backend<P: Platform> {
    type Context;

    fn request(
        &mut self,
        client_ctx: &mut ClientContext,
        backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let _ = (client_ctx, backend_ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
}

pub trait Dispatch<P: Platform> {
    type BackendId: 'static;
    type ExtensionId: TryFrom<u8, Error = Error>;
    type Context: Default;

    fn request(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let _ = (backend, ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }

    fn extension_request(
        &mut self,
        backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut Context<Self::Context>,
        request: &request::Extension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::Extension, Error> {
        let _ = (backend, extension, ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
}

impl<P: Platform> Dispatch<P> for () {
    type BackendId = NoId;
    type ExtensionId = NoId;
    type Context = ();
}

pub enum NoId {}

impl TryFrom<u8> for NoId {
    type Error = Error;

    fn try_from(_: u8) -> Result<Self, Self::Error> {
        Err(Error::InternalError)
    }
}

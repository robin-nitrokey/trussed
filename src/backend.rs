use crate::{
    api::{Reply, Request},
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
}

impl<P: Platform> Dispatch<P> for () {
    type BackendId = ();
    type Context = ();
}

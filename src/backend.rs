use crate::{
    api::{Reply, Request},
    error::Error,
    platform::Platform,
    service::ServiceResources,
    types::ClientContext,
};

pub enum BackendId<C> {
    Software,
    Custom(C),
}

pub trait Backend<P: Platform> {
    fn request(
        &mut self,
        client_ctx: &mut ClientContext,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error>;
}

pub trait Dispatch<P: Platform> {
    type BackendId: 'static;

    fn request(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut ClientContext,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let _ = (backend, ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
}

impl<P: Platform> Dispatch<P> for () {
    type BackendId = ();
}

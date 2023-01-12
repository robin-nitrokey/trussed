#![allow(clippy::transmute_ptr_to_ptr)]

use interchange::{Interchange, Responder};

use crate::{
    api::{Reply, Request},
    error::Result,
    types::ClientContext,
};

pub trait TrussedInterchange<B: 'static>:
    Interchange<REQUEST = Request<B>, RESPONSE = Result<Reply>> + 'static
{
}

impl<B: 'static, I: Interchange<REQUEST = Request<B>, RESPONSE = Result<Reply>> + 'static>
    TrussedInterchange<B> for I
{
}

cfg_if::cfg_if! {
    if #[cfg(feature = "clients-12")] {
        pub const CLIENT_COUNT: usize = 12;
    } else if #[cfg(feature = "clients-11")] {
        pub const CLIENT_COUNT: usize = 11;
    } else if #[cfg(feature = "clients-10")] {
        pub const CLIENT_COUNT: usize = 10;
    } else if #[cfg(feature = "clients-9")] {
        pub const CLIENT_COUNT: usize = 9;
    } else if #[cfg(feature = "clients-8")] {
        pub const CLIENT_COUNT: usize = 8;
    } else if #[cfg(feature = "clients-7")] {
        pub const CLIENT_COUNT: usize = 7;
    } else if #[cfg(feature = "clients-6")] {
        pub const CLIENT_COUNT: usize = 6;
    } else if #[cfg(feature = "clients-5")] {
        pub const CLIENT_COUNT: usize = 5;
    } else if #[cfg(feature = "clients-4")] {
        pub const CLIENT_COUNT: usize = 4;
    } else if #[cfg(feature = "clients-3")] {
        pub const CLIENT_COUNT: usize = 3;
    } else if #[cfg(feature = "clients-2")] {
        pub const CLIENT_COUNT: usize = 2;
    } else if #[cfg(feature = "clients-1")] {
        pub const CLIENT_COUNT: usize = 1;
    } else {
        compile_error!("missing clients feature");
    }
}

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint<B: 'static, I: Interchange + 'static> {
    pub interchange: Responder<I>,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub client_ctx: ClientContext<B>,
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;

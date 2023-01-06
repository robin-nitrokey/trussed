macro_rules! generate_enums {
    ($($which:ident$(<$param:ident>)?: $index:literal)*) => {

    #[derive(Clone, Eq, PartialEq, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Request<B> {
        DummyRequest, // for testing
        $(
        $which(request::$which$(<$param>)?),
        )*
    }

    #[derive(Clone, Eq, PartialEq, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Reply {
        DummyReply, // for testing
        $(
        $which(reply::$which),
        )*
    }

    impl<B> From<&Request<B>> for u8 {
        fn from(request: &Request<B>) -> u8 {
            match request {
                Request::DummyRequest => 0,
                $(
                Request::$which(_) => $index,
                )*
            }
        }
    }

    impl From<&Reply> for u8 {
        fn from(reply: &Reply) -> u8 {
            match reply {
                Reply::DummyReply => 0,
                $(
                Reply::$which(_) => $index,
                )*
            }
        }
    }

}}

macro_rules! impl_request {
    ($(
        $request:ident$(<$param:ident>)?:
            $(- $name:tt: $type:path)*
    )*)
        => {$(
    #[derive(Clone, Eq, PartialEq, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
    pub struct $request$(<$param>)? {
        $(
            pub $name: $type,
        )*
    }

    impl<B> From<$request$(<$param>)?> for Request<B> {
        fn from(request: $request$(<$param>)?) -> Self {
            Self::$request(request)
        }
    }

    )*}
}

macro_rules! impl_reply {
    ($(
        $reply:ident:
            $(- $name:tt: $type:ty)*
    )*)
        => {$(

    #[derive(Clone, Eq, PartialEq, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
    pub struct $reply {
        $(
            pub $name: $type,
        )*
    }

    // impl core::convert::TryFrom<Reply> for $reply {
    //     type Error = ();
    //     fn try_from(reply: Reply) -> Result<reply::$reply, Self::Error> {
    //         match reply {
    //             Reply::$reply(reply) => Ok(reply),
    //             _ => Err(()),
    //         }
    //     }
    // }

    impl From<Reply> for $reply {
        fn from(reply: Reply) -> reply::$reply {
            match reply {
                Reply::$reply(reply) => reply,
                _ => { unsafe { unreachable_unchecked() } }
            }
        }
    }

    )*}
}

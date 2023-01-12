use chacha20::ChaCha8Rng;
use cosey::Bytes;
use littlefs2::path::PathBuf;

use crate::{
    api::{reply, Reply, Request},
    config::MAX_PIN_LENGTH,
    error::{Error, Result},
    platform::Platform,
    service::{key, ServiceResources},
    store::{self, keystore::ClientKeystore, Store},
    types::{ClientContext, Location, Permission, Policy, ServiceBackend},
};

mod auth_state;
use auth_state::AuthState;

pub struct SoftwareAuthBackend {
    pub rng_state: Option<ChaCha8Rng>,
}

impl SoftwareAuthBackend {
    fn policy_path(item_path: &PathBuf) -> PathBuf {
        let p = item_path.as_str_ref_with_trailing_nul().as_bytes();
        let suffix = ".policy".as_bytes();
        let nul: [u8; 1] = [0];

        let mut path = Bytes::<1024>::new();
        path.extend_from_slice(&p[..p.len() - 1]).unwrap();
        path.extend_from_slice(suffix).unwrap();
        path.extend_from_slice(&nul).unwrap();
        PathBuf::from(path.as_slice())
    }

    fn write_policy_for<S: Store>(
        &mut self,
        plat_store: S,
        path: &PathBuf,
        policy: Policy,
    ) -> Result<()> {
        let policy_path = Self::policy_path(path);
        let serialized: Bytes<256> =
            crate::cbor_serialize_bytes(&policy).map_err(|_| Error::CborError)?;
        store::store(
            plat_store,
            Location::Internal,
            &policy_path,
            serialized.as_slice(),
        )
    }

    fn read_policy_for<S: Store>(&mut self, plat_store: S, path: &PathBuf) -> Result<Policy> {
        // @TODO: check for existance
        let policy_path = Self::policy_path(path);
        let policy: Bytes<256> = store::read(plat_store, Location::Internal, &policy_path)?;
        crate::cbor_deserialize(policy.as_slice()).map_err(|_| Error::CborError)
    }

    fn check_permission<B, S: Store>(
        &mut self,
        plat_store: S,
        auth_state: &mut AuthState<S>,
        client_ctx: &ClientContext<B>,
        perm: Permission,
        keypath: &PathBuf,
    ) -> Result<()> {
        if !auth_state.check(client_ctx.context, &client_ctx.pin)? {
            return Err(Error::PermissionDenied);
        }

        let policy = self.read_policy_for(plat_store, &keypath)?;

        if !policy.is_permitted(client_ctx.context, perm) {
            debug_now!("operation not permitted!");
            return Err(Error::PermissionDenied);
        };
        Ok(())
    }
}

impl<P: Platform> ServiceBackend<P> for SoftwareAuthBackend {
    #[inline(never)]
    fn reply_to(
        &mut self,
        client_ctx: &mut ClientContext<P::B>,
        request: &Request<P::B>,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply> {
        let store = resources.platform().store();
        let keystore = &mut ClientKeystore::new(
            client_ctx.path.clone(),
            resources.rng().map_err(|_| Error::EntropyMalfunction)?,
            store,
        );

        // client-local authentication state
        let mut auth_state = AuthState::new(store, &client_ctx);

        match request {
            Request::DummyRequest => Ok(Reply::DummyReply),

            // Part 1: proper requests handled by this backend
            Request::SetAuthContext(request) => {
                if request.pin.len() > MAX_PIN_LENGTH {
                    return Err(Error::InternalError);
                }

                auth_state.check(request.context, &request.pin)?;

                client_ctx.context = request.context;
                /*client_ctx.pin.clear();
                client_ctx.pin.extend_from_slice(&request.pin);*/
                client_ctx.pin = request.pin.clone();

                debug_now!(
                    "setting auth context: {:?} with pin: {:?}",
                    request.context,
                    request.pin
                );

                Ok(Reply::SetAuthContext(reply::SetAuthContext {}))
            }

            Request::CheckAuthContext(request) => auth_state
                .check(request.context, &request.pin)
                .map(|o| Reply::CheckAuthContext(reply::CheckAuthContext { authorized: o })),

            Request::GetAuthRetriesLeft(request) => {
                let out = auth_state.retries(request.context);
                Ok(Reply::GetAuthRetriesLeft(reply::GetAuthRetriesLeft {
                    retries_left: out,
                }))
            }

            Request::WriteAuthContext(request) => {
                auth_state.check(client_ctx.context, &client_ctx.pin)?;

                auth_state.set(client_ctx.context, &request.new_pin)?;
                client_ctx.pin = request.new_pin.clone();

                auth_state
                    .write()
                    .map(|_| Reply::WriteAuthContext(reply::WriteAuthContext {}))
            }

            Request::SetCreationPolicy(request) => {
                client_ctx.creation_policy = request.policy;
                Ok(Reply::SetCreationPolicy(reply::SetCreationPolicy {}))
            }

            // Part 2: wrapped requests (key generation)
            Request::GenerateKey(_) => {
                // todo: generating a key is essentially an operation allowed for anyone?
                let result = resources.reply_to(client_ctx, request);

                // write policy file, after successful generation using `creation_policy`
                if let Ok(Reply::GenerateKey(val)) = &result {
                    let path = keystore.key_path(key::Secrecy::Secret, &val.key);
                    self.write_policy_for(store, &path, client_ctx.creation_policy)?;
                }

                result
            }

            Request::GenerateSecretKey(_) => {
                // todo: same as GenerateKey ?
                let result = resources.reply_to(client_ctx, request);

                // write policy file, after successful generation using `creation_policy`
                if let Ok(Reply::GenerateSecretKey(val)) = &result {
                    let path = keystore.key_path(key::Secrecy::Secret, &val.key);
                    self.write_policy_for(store, &path, client_ctx.creation_policy)?;
                }

                result
            }

            request => {
                // Part 3: requests delegated to the software backend,
                // maybe with added permission checks

                let check = match request {
                    Request::Agree(request) => {
                        Some((Permission::new().with_agree(true), &request.private_key))
                    }
                    Request::Attest(request) => {
                        Some((Permission::new().with_attest(true), &request.private_key))
                    }
                    Request::Decrypt(request) => {
                        Some((Permission::new().with_decrypt(true), &request.key))
                    }
                    Request::DeriveKey(request) => {
                        Some((Permission::new().with_derive(true), &request.base_key))
                    }
                    Request::Encrypt(request) => {
                        Some((Permission::new().with_encrypt(true), &request.key))
                    }
                    Request::Delete(request) => {
                        // todo: write permission == delete permission ? yes/no ?
                        Some((Permission::new().with_write(true), &request.key))
                    }
                    Request::DeleteAllKeys(_) => {
                        // todo: not gated currently, global permissions? client-non-key-specific permissions?
                        None
                    }
                    Request::SerializeKey(request) => {
                        // todo: how to differentiate between public and private here?
                        Some((Permission::new().with_serialize(true), &request.key))
                    }
                    Request::Sign(request) => {
                        Some((Permission::new().with_sign(true), &request.key))
                    }
                    Request::UnwrapKey(request) => {
                        Some((Permission::new().with_unwrap(true), &request.wrapping_key))
                    }
                    Request::Verify(request) => {
                        Some((Permission::new().with_verify(true), &request.key))
                    }
                    Request::WrapKey(request) => {
                        Some((Permission::new().with_wrap(true), &request.wrapping_key))
                    }
                    _ => None,
                };

                if let Some((permission, key)) = check {
                    self.check_permission(
                        store,
                        &mut auth_state,
                        client_ctx,
                        permission,
                        &keystore.key_path(key::Secrecy::Secret, key),
                    )?;
                }

                resources.reply_to(client_ctx, request)
            }
        }
    }
}

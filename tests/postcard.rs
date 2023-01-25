use std::fmt::{self, Debug, Formatter};

use heapless_bytes::Bytes;
use quickcheck::{Arbitrary, Gen, quickcheck};
use trussed::{api::reply::Encrypt, config::{MAX_MESSAGE_LENGTH, MAX_SHORT_DATA_LENGTH}, types::Message};

#[derive(Clone, Default)]
struct TestBytes<const N: usize>(Bytes<N>);

impl<const N: usize> Arbitrary for TestBytes<N> {
    fn arbitrary(g: &mut Gen) -> Self {
        let n = g.size().max(N);
        let mut data = Vec::new();
        for _ in 0..n {
            data.push(u8::arbitrary(g));
        }
        Self(Bytes::from_slice(&data).unwrap())
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let v = self.0.as_slice().to_owned();
        Box::new(v.shrink().map(|s| Self(Bytes::from_slice(&s).unwrap())))
    }
}

impl<const N: usize> Debug for TestBytes<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

type TestMessage = TestBytes<MAX_MESSAGE_LENGTH>;
type TestShortData = TestBytes<MAX_SHORT_DATA_LENGTH>;

fn deserialize_varint<'a>(data: &'a [u8], n: &mut usize) -> Result<&'a [u8], ()> {
    assert!(!data.is_empty());
    if (data[0] & 0x80) == 0 {
        *n |= (data[0] & 0x7F) as usize;
        Ok(&data[1..])
    } else {
        assert!(data.len() > 1);
        *n |= (data[1] & 0x7F) as usize;
        *n <<= 7;
        *n |= (data[0] & 0x7F) as usize;
        Ok(&data[2..])
    }
}

fn deserialize_bytes<'a, const N: usize>(data: &'a [u8], bytes: &mut Bytes<N>) -> Result<&'a [u8], ()> {
    // bytes = varint + data
    let mut n = 0;
    let data = deserialize_varint(data, &mut n)?;
    assert!(n <= data.len());
    let (b, data) = data.split_at(n);
    bytes.extend_from_slice(b).map_err(|_| ())?;
    Ok(data)
}

fn deserialize_usize<'a>(data: &'a [u8], n: &mut usize) -> Result<&'a [u8], ()> {
    assert!(data.len() >= 8);
    *n = u64::from_le_bytes(data[..8].try_into().unwrap()) as _;
    Ok(&data[8..])
}

fn deserialize_field<'a, const N: usize>(data: &'a [u8], idx: usize, bytes: &mut Bytes<N>) -> Result<&'a [u8], ()> {
    let mut i = 0;
    let data = deserialize_usize(data, &mut i)?;
    assert_eq!(i, idx);
    deserialize_bytes(data, bytes)
}

fn deserialize_encrypt<'a>(data: &'a [u8], encrypt: &mut Encrypt) -> Result<&'a [u8], ()> {
    assert!(!data.is_empty());
    assert_eq!(data[0], 3);

    let data = &data[1..];
    let data = deserialize_field(data, 0, &mut encrypt.ciphertext)?;
    let data = deserialize_field(data, 1, &mut encrypt.nonce)?;
    let data = deserialize_field(data, 2, &mut encrypt.tag)?;

    Ok(data)
}

quickcheck! {
    fn test_deserialize_message(message: TestMessage) -> bool {
        let serialized = postcard::to_allocvec(&message.0).unwrap();
        let mut deserialized = Message::default();
        let data = deserialize_bytes(&serialized, &mut deserialized).unwrap();
        assert!(data.is_empty());
        &message.0 == &deserialized
    }

    fn test_deserialize_encrypt(ciphertext: TestMessage, nonce: TestShortData, tag: TestShortData) -> bool {
        println!("Test case:");
        println!("  ciphertext = {ciphertext:?}");
        println!("  nonce = {nonce:?}");
        println!("  tag = {tag:?}");
        let encrypt = Encrypt {
            ciphertext: ciphertext.0,
            nonce: nonce.0,
            tag: tag.0,
        };
        let serialized = postcard::to_allocvec(&encrypt).unwrap();
        println!("Serialized:");
        println!("  {}", hex::encode(&serialized));
        let mut deserialized = Encrypt {
            ciphertext: Default::default(),
            nonce: Default::default(),
            tag: Default::default(),
        };
        let data = deserialize_encrypt(&serialized, &mut deserialized).unwrap();
        assert!(data.is_empty());
        encrypt == deserialized
    }
}

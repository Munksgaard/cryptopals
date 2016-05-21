#![feature(type_ascription)]

extern crate raes;
extern crate pkcs7pad;

use raes::{aes, ecb};
use pkcs7pad::{pad,unpad};

static RANDOM_KEY: &'static[u8] = &[237, 95, 149, 233,
                                    237, 193, 119, 201,
                                    208, 161, 88, 215,
                                    226, 224, 134, 233];

fn kv_decode<'a>(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();

    for kv in input.split(|&x| x == b'&') {
        let mut tmp = kv.split(|&x| x == b'=');
        match (tmp.next(), tmp.next()) {
            (Some(k), Some(v)) => {
                result.push((k.to_vec(), v.to_vec()));},
            _ => panic!("Invalid input"),
        }
    }

    result
}

#[test]
fn test_kv_decode() {
    let input = b"foo=bar&baz=qux&zap=zazzle";

    let result = kv_decode(input);

    let expected = vec!((b"foo".to_vec(), b"bar".to_vec()),
                        (b"baz".to_vec(), b"qux".to_vec()),
                        (b"zap".to_vec(), b"zazzle".to_vec()));

    assert_eq!(result, expected);
}

fn kv_encode(input: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut result = Vec::new();
    for &(ref key, ref val) in input {
        result.extend_from_slice(&key);
        result.push(b'=');
        result.extend_from_slice(&val);
        result.push(b'&');
    }

    result.pop();

    result
}

#[test]
fn test_kv_encode() {
    let input: &[(Vec<u8>, Vec<u8>)] = &[(b"foo".to_vec(), b"bar".to_vec()),
                                         (b"baz".to_vec(), b"qux".to_vec()),
                                         (b"zap".to_vec(), b"zazzle".to_vec())];

    let result = kv_encode(input);

    let expected = b"foo=bar&baz=qux&zap=zazzle";

    assert_eq!(result, expected);
}

#[test]
fn test_kv_encode_empty() {
    let input = &[];

    let result = kv_encode(input);

    let expected = &[];

    assert_eq!(result, expected);
}

#[test]
fn test_kv_encode_decode_isomorph() {
    let input = b"foo=bar&baz=qux&zap=zazzle";

    let decoded = kv_decode(input);

    let encoded = kv_encode(&decoded);

    assert_eq!(encoded, input);
}

fn profile_for(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let stripped: Vec<u8> = input
        .iter()
        .filter_map(|&c| if c != b'&' && c != b'=' { Some(c) } else { None })
        .collect();

    let mut result: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    result.push((b"email".to_vec(), stripped));
    result.push((b"uid".to_vec(), b"10".to_vec()));
    result.push((b"role".to_vec(), b"user".to_vec()));
    result
}

#[test]
fn test_profile_for() {
    let input = b"foo@bar.com&role=admin";

    let result = profile_for(input);

    let expected = vec!((b"email".to_vec(), b"foo@bar.comroleadmin".to_vec()),
                        (b"uid".to_vec(), b"10".to_vec()),
                        (b"role".to_vec(), b"user".to_vec()));

    assert_eq!(result, expected);
}

fn encrypt_profile(input: &[u8]) -> Vec<u8>{
    let profile = kv_encode(&profile_for(input));
    ecb::ecb(aes::encrypt, &pad(&profile, 16), RANDOM_KEY)
}

fn decrypt_profile<'a>(input: &'a [u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = unpad(&ecb::ecb(aes::decrypt, input, RANDOM_KEY));
    kv_decode(&bytes)
}

#[test]
fn test_encrypt_decrypt_isomorph() {
    let input = b"john";

    let profile = kv_encode(&profile_for(input));

    let encrypted = encrypt_profile(input);

    let decrypted = kv_encode(&decrypt_profile(&encrypted));

    println!("profile: {:?}", String::from_utf8(profile.clone()).unwrap());
    println!("decrypted: {:?}", String::from_utf8(decrypted.clone()).unwrap());

    assert_eq!(&profile, &decrypted);
}

fn main() {
    // Thirteen 'A's make 'role=' align just to the left edge of the block boundary.
    let eql_profile = encrypt_profile(b"AAAAAAAAAAAAA");
    let eql = &eql_profile[0 .. 32];
    // eql = "email=1234567890123&uid=10&role=

    // Ten 'A's make admin appear on the right side of the block boundary
    let admin_profile = encrypt_profile(b"AAAAAAAAAAadmin");
    let adm = &admin_profile[16..32];
    // adm = "admin&uid=10&rol";

    // 14 'A's make "=user" appear on the right side of a block boundary
    let padding_profile = encrypt_profile(b"AAAAAAAAAAAAAA");
    let padding = &padding_profile[32..48];
    // padding = "=user";

    let mut res = Vec::new();
    res.extend_from_slice(&eql);
    res.extend_from_slice(&adm);
    res.extend_from_slice(&padding);

    let decrypted = decrypt_profile(&res);
    println!("{}", String::from_utf8(kv_encode(&decrypted)).unwrap());
}

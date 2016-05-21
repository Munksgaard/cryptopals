extern crate rand;
extern crate base64;
extern crate raes;
extern crate pkcs7pad;

use raes::{cbc, aes};
use rand::Rng;

static ENCRYPTED_STRINGS: [&'static [u8]; 10] =
    [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
     b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
     b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
     b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
     b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
     b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
     b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
     b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
     b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
     b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"];

static RANDOM_KEY: &'static [u8] = &[102, 104, 72, 211,
                                     59, 187, 173, 237,
                                     203, 21, 4, 83,
                                     153, 198, 36, 50];

fn random_iv() -> Vec<u8> {
    let mut buf = Vec::new();

    for _ in 0..16 {
        buf.push(rand::random());
    }

    buf
}

fn pad_and_encrypt(plain: &[u8], iv: &[u8]) -> Vec<u8> {
    let padded = pkcs7pad::pad(&plain, 16);

    let cipher = cbc::encrypt(aes::encrypt, &padded, RANDOM_KEY, iv);

    cipher
}

fn padding_oracle() -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();

    let plain = base64::decode(rng.choose(&ENCRYPTED_STRINGS).unwrap());

    let iv = random_iv();
    let cipher = pad_and_encrypt(&plain, &iv);

    (cipher, iv)
}

fn validate_padding(cipher: &[u8], iv: &[u8]) -> bool {
    let decrypted = cbc::decrypt(aes::decrypt, cipher, RANDOM_KEY, iv);
    if pkcs7pad::validate_padding(&decrypted) {
        true
    } else {
        false
    }
}

#[test]
fn pad_and_validate_test() {
    for _ in 0..10 {
        let (cipher, iv) = padding_oracle();

        assert!(validate_padding(&cipher, &iv));
    }
}

#[test]
fn tamper_last_byte() {
    let (cipher, iv) = padding_oracle();

    assert!(validate_padding(&cipher, &iv));

    let mut tampered = cipher.clone();

    if let Some(x) = tampered.last_mut() {
        *x = 0x01;
    }

    assert!(!validate_padding(&tampered, &iv));
}

#[test]
fn tamper_last_byte_2() {
    let (cipher, iv) = padding_oracle();

    assert!(validate_padding(&cipher, &iv));

    let mut tampered = cipher.clone();

    let len = tampered.len();
    if let Some(x) = tampered.get_mut(len-17) {
        *x = 0x00;
    }

    assert!(!validate_padding(&tampered, &iv));
}

#[cfg(test)]
fn find_last_byte(cipher: &[u8], iv: &[u8]) -> u8 {
    assert_eq!(16, cipher.len());
    assert_eq!(16, iv.len());

    let mut buf = iv.to_vec();

    for guess_ in 0..256 {
        let guess = guess_ as u8;

        buf[15] = guess ^ iv[15] ^ 1;
        if buf[15] == iv[15] {
            continue
        }

        if validate_padding(&cipher, &buf) {
            return guess;
        }
    }

    unreachable!();
}

#[test]
fn test_find_last_byte() {
    for plain_ in ENCRYPTED_STRINGS.iter() {
        let plain = base64::decode(plain_);

        let padded = pkcs7pad::pad(&plain, 16);

        let iv = random_iv();

        let cipher = pad_and_encrypt(&plain, &iv);
        let len = cipher.len();

        let tmp1 = &cipher[len-16..];
        let tmp2 = &cipher[len-32..len-16];
        let byte = find_last_byte(tmp1, tmp2);

        assert_eq!(byte, *padded.last().unwrap());
    }
}

/// Given an encrypted block, the IV, and a list of the bytes that we've already
/// found (starting from the end of the block), replace the bytes at the end to
/// prepare for finding the next byte.
fn replace_padding(cipher: &[u8], iv: &[u8], last_bytes: &[u8]) -> Vec<u8> {
    assert_eq!(16, cipher.len());
    assert_eq!(16, iv.len());

    let n = last_bytes.len() + 1;

    let mut buf = iv.to_vec();

    for i in 1..n {
        buf[16-i] = last_bytes[i-1] ^ iv[16-i] ^ n as u8;
    }

    buf
}

#[test]
fn test_replace_padding() {
    let plain: Vec<u8> = base64::decode(ENCRYPTED_STRINGS.first().unwrap())[..16].to_vec();
    let iv = random_iv();
    let cipher = cbc::encrypt(aes::encrypt, &plain, RANDOM_KEY, &iv);
    let last_byte = find_last_byte(&cipher, &iv);

    let tmp = replace_padding(&cipher, &iv, &[last_byte]);
    let decrypted = cbc::decrypt(aes::decrypt, &cipher, RANDOM_KEY, &tmp);

    assert_eq!(2, decrypted[15]);

    let tmp = replace_padding(&cipher, &iv, &[plain[15], plain[14]]);
    let decrypted = cbc::decrypt(aes::decrypt, &cipher, RANDOM_KEY, &tmp);

    assert_eq!(3, decrypted[14]);
    assert_eq!(3, decrypted[15]);
}

/// Given an encrypted block, but with the last bytes replaced such that the
/// padding is almost correct, find the correct byte at position ix that will
/// make the padding valid.
fn find_byte(cipher: &[u8], iv: &[u8], ix: usize) -> u8 {
    assert_eq!(16, cipher.len());
    assert_eq!(16, iv.len());
    assert!(ix < 16);

    let mut buf = iv.to_vec();

    for guess_ in 0..256 {
        let guess = guess_ as u8;

        buf[ix] = guess ^ iv[ix] ^ (16 - ix as u8);
        if buf[ix] == iv[ix] {
            // If our tampered byte is the same as the original byte,
            // validate_padding will always return true.
            continue
        }

        if validate_padding(&cipher, &buf) {
            return guess;
        }
    }

    // If we reach this point, the plaintext has been padded with exactly 16-ix
    // characters. So the original byte must be the first padding byte in which
    // case the above check for `buf[ix] == iv[ix]` will have caused us to skip
    // the correct guess. This can only happen if the byte we're tring to guess
    // is the first byte of the original padding. We therefore know that the
    // correct byte is `16 - ix`, because that is how many bytes of padding
    // there must be.
    16 - ix as u8
}

#[test]
fn test_find_byte() {
    for plain_ in ENCRYPTED_STRINGS.iter() {
        let plain = base64::decode(plain_);

        let padded = pkcs7pad::pad(&plain, 16);

        let iv = random_iv();

        let cipher = pad_and_encrypt(&plain, &iv);
        let len = cipher.len();

        let tmp1 = &cipher[len-16..];
        let tmp2 = &cipher[len-32..len-16];
        let byte = find_byte(tmp1, tmp2, 15);

        assert_eq!(byte, *padded.last().unwrap());
    }
}

#[test]
fn test_find_byte_2() {
    let plain: Vec<u8> = base64::decode(ENCRYPTED_STRINGS.first().unwrap())[..16].to_vec();

    let iv = random_iv();
    let cipher = cbc::encrypt(aes::encrypt, &plain, RANDOM_KEY, &iv);
    let last_byte = find_byte(&cipher, &iv, 15);
    assert_eq!(last_byte, plain[15]);

    let tmp = replace_padding(&cipher, &iv, &[last_byte]);
    let second_last_byte = find_byte(&cipher, &tmp, 14);
    assert_eq!(second_last_byte, plain[14]);

    let tmp = replace_padding(&cipher, &iv, &[last_byte, second_last_byte]);
    let third_last_byte = find_byte(&cipher, &tmp, 13);
    assert_eq!(third_last_byte, plain[13]);
}

/// Given an encrypted block and an IV, use `replace_padding` and `find_byte` to
/// identify all the encrypted bytes in the block.
fn find_block(cipher: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(16, cipher.len());
    assert_eq!(16, iv.len());

    let mut buf: Vec<u8> = Vec::new();

    for i in (0..16).rev() {
        let iv_ = replace_padding(&cipher, &iv, &buf);

        buf.push(find_byte(&cipher, &iv_, i));
    }

    buf.iter().rev().map(|&x| x).collect()
}

#[test]
fn test_find_block() {
    let plain: Vec<u8> = base64::decode(ENCRYPTED_STRINGS.first().unwrap())[..16].to_vec();
    let iv = random_iv();
    let cipher = cbc::encrypt(aes::encrypt, &plain, RANDOM_KEY, &iv);

    let decrypted = find_block(&cipher, &iv);

    assert_eq!(decrypted, plain);
}

/// Given an encrypted text and an IV, use `find_block` to decrypt the encrypted
/// text.
fn find_plain(cipher: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(0, cipher.len() % 16);
    assert_eq!(16, iv.len());

    let mut result = Vec::new();
    let mut last_block = iv.to_vec();

    for block in cipher.chunks(16) {
        let decrypted = find_block(block, &last_block);
        result.extend_from_slice(&decrypted);
        last_block = block.to_vec();
    }

    result
}

#[test]
fn test_find_plain() {
    let plain: Vec<u8> = base64::decode(ENCRYPTED_STRINGS.first().unwrap())[..32].to_vec();
    let iv = random_iv();
    let cipher = cbc::encrypt(aes::encrypt, &plain, RANDOM_KEY, &iv);

    let decrypted = find_plain(&cipher, &iv);

    assert_eq!(decrypted, plain);
}

#[test]
fn test_find_plain2() {
    let plain: Vec<u8> = base64::decode(ENCRYPTED_STRINGS.first().unwrap())[..16].to_vec();
    let iv = random_iv();
    let cipher = pad_and_encrypt(&plain, &iv);

    let decrypted = find_plain(&cipher, &iv);

    let unpadded = pkcs7pad::unpad(&decrypted);

    assert_eq!(unpadded, Some(plain));
}

#[test]
fn test_find_plain3() {
    let plain: Vec<u8> = base64::decode(ENCRYPTED_STRINGS.first().unwrap());
    let iv = random_iv();
    let cipher = pad_and_encrypt(&plain, &iv);

    let decrypted = find_plain(&cipher, &iv);

    let unpadded = pkcs7pad::unpad(&decrypted);

    assert_eq!(unpadded, Some(plain));
}

#[test]
fn test_find_plain4() {
    for s in ENCRYPTED_STRINGS.iter() {
        let plain = base64::decode(s);
        let iv = random_iv();

        let cipher = pad_and_encrypt(&plain, &iv);

        let decrypted = find_plain(&cipher, &iv);

        let unpadded = pkcs7pad::unpad(&decrypted);

        assert_eq!(unpadded, Some(plain));
    }
}

fn main() {
    let (cipher, iv) = padding_oracle();

    let decrypted = find_plain(&cipher, &iv);

    let unpadded = pkcs7pad::unpad(&decrypted).unwrap();

    let s = String::from_utf8(unpadded).unwrap();

    println!("{}", s);
}

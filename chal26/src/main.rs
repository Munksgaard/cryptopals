extern crate raes;
extern crate pkcs7pad;

use raes::{aes, ctr};

/* CTR bitflipping
 * There are people in the world that believe that CTR resists bit flipping
 * attacks of the kind to which CBC mode is susceptible.
 *
 * Re-implement the CBC bitflipping exercise from earlier to use CTR mode
 * instead of CBC mode. Inject an "admin=true" token.
 */

static RANDOM_KEY: &'static [u8] = &[21, 74, 153, 147,
                                     244, 100, 141, 128,
                                     30, 176, 207, 176,
                                     202, 11, 105, 107];

fn escape_semicolon_and_equals(input: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    for x in input {
        if *x == b';' {
            buf.extend_from_slice(b"%3B");
        } else if *x == b'=' {
            buf.extend_from_slice(b"%3D");
        } else {
            buf.push(*x);
        }
    }

    buf
}

#[test]
fn test_escape_semicolon_and_equals() {
    let input = b"Hello world!";
    let expected: &[u8] = b"Hello world!";

    assert!(escape_semicolon_and_equals(input) == expected);

    let input = b"comment1=cooking%20MCs;userdata=";
    let expected: &[u8] = b"comment1%3Dcooking%20MCs%3Buserdata%3D";
    assert!(escape_semicolon_and_equals(input) == expected);
}

fn append_and_escape(input: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
    let escaped = escape_semicolon_and_equals(&input);
    buf.extend_from_slice(&escaped);
    buf.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");

    buf
}

#[test]
fn test_append_and_escape() {
    let input = b"Hello world!";
    let expected = b"comment1=cooking%20MCs;userdata=Hello world!;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    assert!(append_and_escape(input) == expected);

    let input = b"comment1=cooking%20MCs;userdata=";
    let expected = b"comment1=cooking%20MCs;userdata=comment1%3Dcooking%20MCs%3Buserdata%3D;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    assert!(append_and_escape(input) == expected);
}

fn scramble_text(input: &[u8]) -> Vec<u8> {
    let appended = append_and_escape(input);

    let padded = pkcs7pad::pad(&appended, 16);

    let encrypted = ctr::ctr(aes::encrypt, &padded, RANDOM_KEY, 0);

    encrypted
}

#[test]
fn test_scramble_text() {
    let scrambled = scramble_text(b"Hello world!");
    let expected = b"comment1=cooking%20MCs;userdata=Hello world!;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    let decrypted = ctr::ctr(aes::encrypt, &scrambled, RANDOM_KEY, 0);

    assert_eq!(pkcs7pad::unpad(&decrypted).unwrap(), expected);
}

fn find_admin(cipher: &[u8]) -> bool {
    let decrypted = ctr::ctr(aes::encrypt, cipher, RANDOM_KEY, 0);

    let split = decrypted.split(|x| *x == b';').position(|s| s == b"admin=true");

    return split.is_some();
}

#[test]
fn find_admin_test() {
    let contains_admin = b"comment1=cooking%20MCs;admin=true;John=hej%20dig";
    let padded = pkcs7pad::pad(contains_admin, 16);
    let encrypted = ctr::ctr(aes::encrypt, &padded, RANDOM_KEY, 0);

    assert!(find_admin(&encrypted));

    let admin_string = b"bla;admin=true";
    let scrambled = scramble_text(admin_string);

    assert!(!find_admin(&scrambled));
}

fn insert_admin<F>(f: F) -> Vec<u8>
    where F: Fn(&[u8]) -> Vec<u8>
{
    let mut input = Vec::new();
    // First insert at least 16 bytes (the size of one block) of all As
    input.extend_from_slice(b"AAAAAAAAAAAAAAAA");
    // Then, in the next block it should say "AadminAtrue"
    input.extend_from_slice(b"AadminAtrue");

    let cipher = f(&input);

    for idx in 0..cipher.len() - 6 {
        let mut buf = cipher.to_vec();

        buf[idx] = buf[idx] ^ b'A' ^ b';';
        buf[idx + 6] = buf[idx + 6] ^ b'A' ^ b'=';

        if let true = find_admin(&buf) {
            return buf;
        }
    }

    panic!("No valid cipher found");
}

#[test]
fn insert_admin_test() {
    assert!(find_admin(&insert_admin(scramble_text)));
}

fn main() {
    assert!(find_admin(&insert_admin(scramble_text)));
}

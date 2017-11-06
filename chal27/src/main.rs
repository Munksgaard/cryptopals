extern crate raes;

use raes::{aes, cbc};

/* Recover the key from CBC with IV=Key
 *
 * Take your code from the CBC exercise and modify it so that it repurposes the
 * key for CBC encryption as the IV.
 *
 * Applications sometimes use the key as an IV on the auspices that both the
 * sender and the receiver have to know the key already, and can save some space
 * by using it as both a key and an IV.
 *
 * Using the key as an IV is insecure; an attacker that can modify ciphertext in
 * flight can get the receiver to decrypt a value that will reveal the key.
 *
 * The CBC code from exercise 16 encrypts a URL string. Verify each byte of the
 * plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant
 * messages should raise an exception or return an error that includes the
 * decrypted plaintext (this happens all the time in real systems, for what it's
 * worth).
 *
 * Use your code to encrypt a message that is at least 3 blocks long:
 *
 *  AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
 *
 * Modify the message (you are now the attacker):
 *
 *   C_1, C_2, C_3 -> C_1, 0, C_1
 *
 * Decrypt the message (you are now the receiver) and raise the appropriate
 * error if high-ASCII is found.
 *
 * As the attacker, recovering the plaintext from the error, extract the key:
 *
 *   P'_1 XOR P'_3
 */

static RANDOM_KEY: &'static [u8] = &[21, 74, 153, 147,
                                     244, 100, 141, 128,
                                     30, 176, 207, 176,
                                     202, 11, 105, 107];

fn encrypt(input: &[u8]) -> Vec<u8> {
    cbc::encrypt(aes::encrypt, input, RANDOM_KEY, RANDOM_KEY)
}

fn decrypt_and_verify(input: &[u8]) -> Result<(), Vec<u8>> {
    let decrypted = cbc::decrypt(aes::decrypt, &input, RANDOM_KEY, RANDOM_KEY);
    if decrypted.iter().all(|&c| c < 128) {
        Ok(())
    } else {
        Err(decrypted)
    }
}

fn breakit() {
    let input = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let encrypted = encrypt(input);
    let mut tampered = encrypted[0..16].to_vec();
    tampered.extend_from_slice(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    tampered.extend_from_slice(&encrypted[0..16]);
    match decrypt_and_verify(&tampered) {
        Ok(()) => println!("Key not found"),
        Err(decrypted) => {
            let key = decrypted
                .iter()
                .take(16)
                .zip(decrypted.iter().skip(32).take(16))
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>();
            println!("Key found: {:?}", key)
        }
    }
}

fn main() {
    breakit()
}

use base64::prelude::*;
use openssl::symm::{decrypt, Cipher};

const CIPHERTEXT: &str = include_str!("data/challenge_7");
const KEY: &str = "YELLOW SUBMARINE";

pub fn solve() -> Vec<u8> {
    let input = BASE64_STANDARD
        .decode(CIPHERTEXT.split_whitespace().collect::<String>())
        .unwrap();
    let key = KEY.as_bytes();
    let cipher = Cipher::aes_128_ecb();

    decrypt(cipher, key, None, &input).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decrypt_aes_ecb() {
        assert_eq!(
            format!("{:?}", md5::compute(solve())),
            "6187f6e338437e32f9cfc89ff6ee3b4d"
        );
    }
}

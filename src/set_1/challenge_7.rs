use base64::prelude::*;
use cryptopals::{ecb_decrypt, unpad_pkcs7};

const CIPHERTEXT: &str = include_str!("data/challenge_7");
const KEY: &[u8] = b"YELLOW SUBMARINE";

pub fn solve() -> Vec<u8> {
    let input = BASE64_STANDARD
        .decode(CIPHERTEXT.split_whitespace().collect::<String>())
        .unwrap();
    unpad_pkcs7(&ecb_decrypt(&input, KEY))
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

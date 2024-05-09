use base64::prelude::*;
use cryptopals::cbc_decrypt;

const CIPHERTEXT: &str = include_str!("data/challenge_10");

pub fn solve() -> Vec<u8> {
    let key = "YELLOW SUBMARINE";
    let input = BASE64_STANDARD
        .decode(CIPHERTEXT.split_whitespace().collect::<String>())
        .unwrap();
    cbc_decrypt(&input, key.as_bytes(), &vec![0; 16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_10() {
        assert_eq!(
            format!("{:?}", md5::compute(solve())),
            "6187f6e338437e32f9cfc89ff6ee3b4d"
        );
    }
}

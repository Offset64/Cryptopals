use base64::prelude::*;

const CIPHERTEXT: &str = include_str!("data/challenge_7");

fn main() {
    println!("{:x}", md5::compute(solve()))
}

fn solve() -> Vec<u8> {
    let input = BASE64_STANDARD
        .decode(CIPHERTEXT.split_whitespace().collect::<String>())
        .unwrap();

    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decrypt_aes_ecb() {
        assert_eq!(
            format!("{:?}", md5::compute(solve())),
            ""
        );
    }
}
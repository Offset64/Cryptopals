use cryptopals::minimum_entropy;

const CIPHERTEXT: &str = include_str!("data/challenge_8");

pub fn solve() -> Vec<u8> {
    let inputs: Vec<_> = CIPHERTEXT
        .split_whitespace()
        .map(|input| hex::decode(input).unwrap())
        .collect();
    // The input with the smallest entropy is the one that was encrypted with ECB.
    minimum_entropy::<Vec<u8>, Vec<_>>(&inputs).to_owned()
    
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_challenge_8() {
        assert_eq!(format!("{:?}", md5::compute(solve())), "d87da70d0d0fd0f3519ba2b7e7118683");
    }
}

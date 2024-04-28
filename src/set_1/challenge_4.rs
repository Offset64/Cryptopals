use cryptopals::single_byte_xor_crack;

const INPUT: &str = include_str!("data/challenge_4");

/**
 * A single byte xor was used to encrypt one of the strings in the input
 */
#[allow(dead_code)]
fn main() {
    println!("{:x}", md5::compute(solve()))
}

pub fn solve() -> Vec<u8> {
    let lines: Vec<Vec<u8>> = INPUT
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect();

    let (_, _, result) = lines
        .iter()
        .map(|line| single_byte_xor_crack(&line))
        .max_by_key(|(score, _, _)| *score)
        .unwrap();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_detect_single_byte_xor() {
        assert_eq!(
            format!("{:?}", md5::compute(solve())),
            "90cb2dc65138fac5a9a3ce1b5d570123"
        );
    }
}

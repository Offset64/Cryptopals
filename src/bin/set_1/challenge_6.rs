use std::ops::RangeInclusive;

use base64::prelude::*;
use cryptopals::hamming_distance;

const CIPHERTEXT: &str = include_str!("data/challenge_6");
#[allow(dead_code)]
fn main() {
    println!("{:x}", md5::compute(solve()))
}

pub fn solve() -> Vec<u8> {
    let input = BASE64_STANDARD
        .decode(CIPHERTEXT.split_whitespace().collect::<String>())
        .unwrap();
    let key_size = get_key_size(&input, 2..=40);

    //Each block is all the bytes that were XOR'd with the same byte of the key.
    let blocks = transpose_blocks(&input, key_size);
    //We can now solve each block as if it were single byte XOR.
    let key: Vec<u8> = blocks
        .iter()
        .map(|block| {
            let (_, key, _) = cryptopals::single_byte_xor_crack(&block);
            key
        })
        .collect();
    key
}

fn get_key_size(cipher_bytes: &[u8], range: RangeInclusive<usize>) -> usize {
    range
        .map(|key_size| {
            //Take the first key_size worth of bytes.
            let initial_block = &cipher_bytes[0..key_size];
            //Next we're going to get the average hamming distance against all remaining blocks.
            let distance = cipher_bytes
                .chunks(key_size)
                .skip(1)
                .map(|block| hamming_distance(block, initial_block) as usize)
                .sum::<usize>();
            (distance, key_size)
        })
        .min_by_key(|(distance, _)| *distance)
        .unwrap()
        .1 // Return the key_size which produced the smallest distance.
}

fn transpose_blocks(bytes: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    let mut blocks = vec![Vec::new(); key_size];
    for (i, byte) in bytes.iter().enumerate() {
        blocks[i % key_size].push(*byte);
    }
    blocks
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_repeating_key_xor_key_retrieve() {
        assert_eq!(
            format!("{:?}", md5::compute(solve())),
            "011327c9d6d57189d01c768cd3d6f4a3"
        );
    }
    #[test]
    fn test_repeating_key_xor_decrypt() {
        let key = solve();
        let input = BASE64_STANDARD
            .decode(CIPHERTEXT.split_whitespace().collect::<String>())
            .unwrap();
        let output = cryptopals::repeating_key_xor(&input, &key);
        let decrypted_text = String::from_utf8(output).unwrap();
        assert_eq!(
            format!("{:?}", md5::compute(decrypted_text)),
            "6187f6e338437e32f9cfc89ff6ee3b4d"
        );
    }
}

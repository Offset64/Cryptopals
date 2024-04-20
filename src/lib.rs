pub fn fixed_xor(input_bytes: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    input_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

pub fn single_byte_xor(input_bytes: &[u8], key: u8) -> Vec<u8> {
    input_bytes.iter().map(|&c| c ^ key).collect()
}

pub fn repeating_key_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

pub fn single_byte_xor_crack(input: &[u8]) -> (i32, u8, Vec<u8>) {
    let mut best_score = 0;
    let mut best_key = 0;
    let mut best_output = Vec::new();
    for key in 0..=255 {
        let output = single_byte_xor(&input, key);
        let score = score_text(&output);
        if score > best_score {
            best_score = score;
            best_key = key;
            best_output = output;
        }
    }
    (best_score, best_key, best_output)
}

// Examine data and determine if it is likely to be English text
pub fn score_text(input: &[u8]) -> i32 {
    input
        .iter()
        .map(|&c| match c as char {
            x if "etaoin".contains(x) => 5,
            x if "ETAOIN".contains(x) => 4,
            x if "shrdlu".contains(x) => 3,
            x if "SHRDLU".contains(x) => 2,
            'A'..='z' => 1,
            _ => 0,
        })
        .sum()
}

pub fn hamming_distance(input1: &[u8], input2: &[u8]) -> usize {
    input1
        .iter()
        .zip(input2.iter())
        .map(|(a, b)| (a ^ b).count_ones() )
        .sum::<u32>() as usize
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;
    use hex;
    use super::*;

    #[test]
    fn test_hex_to_base64() {
        let input_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        // convert the hex string to the bytes it represents
        let input_bytes = hex::decode(input_str).unwrap();
        // convert the bytes to a base64 representation
        let output_str = BASE64_STANDARD.encode(input_bytes);
        assert_eq!(
            output_str,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_fixed_xor() {
        let input = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let key = hex::decode("686974207468652062756c6c277320657965").unwrap();
        assert_eq!(
            fixed_xor(&input, &key),
            hex::decode("746865206b696420646f6e277420706c6179").unwrap()
        )
    }

    #[test]
    fn test_repeating_key_xor() {
        let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";
        let output = repeating_key_xor(input, key);
        let expected = hex::decode(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
            a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        )
        .unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_hamming_distance() {
        let input1 = "this is a test";
        let input2 = "wokka wokka!!!";
        let distance = hamming_distance(input1.as_bytes(), input2.as_bytes());
        assert_eq!(distance, 37);
    }
}

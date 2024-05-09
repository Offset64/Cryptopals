use openssl::symm::{Cipher, Crypter, Mode};

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

pub fn hamming_distance(input1: &[u8], input2: &[u8]) -> u32 {
    input1
        .iter()
        .zip(input2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum()
}

pub fn calculate_entropy<'a, I>(input: I) -> f64
where
    I: AsRef<[u8]> + IntoIterator<Item = &'a u8>,
{
    //build histogram of bytes
    let mut histogram = [0; 256];
    for byte in input {
        histogram[*byte as usize] += 1;
    }
    let total_bytes = histogram.iter().sum::<u8>() as f64;

    histogram
        .iter()
        .map(|count| {
            let p = *count as f64 / total_bytes;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

pub fn minimum_entropy<I, T>(iterable: &[I]) -> &[u8]
where
    T: IntoIterator<Item = I>,
    T::Item: AsRef<[u8]> + IntoIterator,
{
    iterable
        .into_iter()
        .min_by_key(|l| {
            let e = calculate_entropy(l.as_ref()) * 100.0;
            e.round() as i32
        })
        .unwrap()
        .as_ref()
}

pub fn pad_pkcs7(input: &[u8], block_size: usize) -> Vec<u8> {
    let required_padding = block_size - (input.len() % block_size);
    let padding_byte = required_padding as u8;
    let padding = vec![padding_byte; required_padding];
    [input, &padding].concat()
}

pub fn unpad_pkcs7(input: &[u8]) -> Vec<u8> {
    input[..input.len() - *input.last().unwrap() as usize].to_vec()
}

pub fn ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    crypter.pad(false);

    let block_size = cipher.block_size();
    let mut output = vec![0; input.len() + block_size];
    let mut count = 0;

    for block in input.chunks(block_size) {
        count += crypter.update(&block, &mut output[count..]).unwrap();
    }
    count += crypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count);
    output
}

pub fn ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    crypter.pad(false);

    let block_size = cipher.block_size();
    let mut output = vec![0; input.len() + block_size];
    let mut count = 0;
    for block in input.chunks(block_size) {
        count += crypter.update(&block, &mut output[count..]).unwrap();
    }
    count += crypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count);
    output
}

pub fn cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut previous_block = iv.to_vec();
    let padded_input = pad_pkcs7(input, 16);
    for block in padded_input.chunks(16) {
        let xored = fixed_xor(&block, &previous_block);
        let encrypted = ecb_encrypt(&xored, key);
        output.extend_from_slice(&encrypted);
        previous_block = encrypted;
    }
    output
}

pub fn cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut previous_block = iv.to_vec();
    for block in input.chunks(16) {
        let decrypted = ecb_decrypt(&block, key);
        let xored = fixed_xor(&decrypted, &previous_block);
        previous_block = block.to_vec();
        output.extend_from_slice(&xored);
    }
    unpad_pkcs7(&output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use hex;

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let key = b"YELLOW SUBMARINE";
        let iv = vec![0; 16];

        let input_1 = b"this is a test";
        let encrypted_1 = cbc_encrypt(input_1, key, &iv);
        let decrypted_1 = cbc_decrypt(&encrypted_1, key, &iv);

        assert_eq!(input_1, &decrypted_1[..]);

        let input_2 = b"this is a test. it's not a clean multiple of 16 bytes.";
        let encrypted_2 = cbc_encrypt(input_2, key, &iv);
        let decrypted_2 = cbc_decrypt(&encrypted_2, key, &iv);

        assert_eq!(input_2, &decrypted_2[..]);
    }

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

    #[test]
    fn test_calculate_entropy() {
        //One normal string and 10 random ones.
        let inputs = vec![
            b"this is a test",
            b"hrvtnnaryggtzy",
            b"ytxnddourbkvwt",
            b"xpauulrvhaszjr",
            b"qeagldsrybdxhf",
            b"rylcfdpjswjxgk",
            b"ugpqoskjqxtwzp",
            b"qykgsecsaqeygm",
            b"dejtsaecglwvjl",
            b"xbqjtpzlxwxuoh",
            b"ucuwznveldxkmr",
        ];
        let tmp: Vec<&[u8]> = inputs.iter().map(|x| x.as_ref()).collect();
        assert_eq!(
            minimum_entropy::<&[u8], Vec<_>>(tmp.as_ref()),
            b"this is a test"
        );
    }
    #[test]
    fn test_pad_pkcs7() {
        let input = b"YELLOW SUBMARINE";
        let block_size = 20;
        let output = pad_pkcs7(input, block_size);
        assert_eq!(output, b"YELLOW SUBMARINE\x04\x04\x04\x04");

        let unpadded = unpad_pkcs7(&output);
        assert_eq!(unpadded, input);
    }
}

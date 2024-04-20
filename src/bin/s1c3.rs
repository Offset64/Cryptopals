use cryptopals::single_byte_xor_crack;

const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

/**
 * A single character was used to XOR this string
 */
fn main() {
    println!("{:x}", md5::compute(solve()))
}

fn solve() -> Vec<u8> {
    let input = hex::decode(INPUT).unwrap();
    let (_, _, output) = single_byte_xor_crack(&input);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_byte_xor_cipher_brute() {
        let result_hash = "2aa4ac426ec0624441a0bee9b6abd80e"; //MD5 hash of the decrypted output. No spoilers here.

        //If the hash of our result, matches the known hash of the correct output, we have successfully decrypted the message.
        assert_eq!(format!("{:x}", md5::compute(solve())), result_hash);
    }
}

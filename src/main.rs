mod set_1;
mod set_2;

use set_1::*;
use set_2::*;
fn main() {
    println!("Set 1: Basics");
    println!("----------------");
    println!("[Challenge  #] [MD5                             ] Description");
    println!(
        "[Challenge  3] [{:x}] Single-byte XOR cipher ",
        md5::compute(challenge_3::solve())
    );
    println!(
        "[Challenge  4] [{:x}] Detect single-character XOR ",
        md5::compute(challenge_4::solve())
    );
    println!(
        "[Challenge  6] [{:x}] Break repeating-key XOR",
        md5::compute(challenge_6::solve())
    );
    println!(
        "[Challenge  7] [{:x}] AES In ECB Mode",
        md5::compute(challenge_7::solve())
    );

    println!(
        "[Challenge  8] [{:x}] Detect AES in ECB mode",
        md5::compute(challenge_8::solve())
    );
    println!("");
    println!("Set 2: Block crypto");
    println!("----------------");
    println!("[Challenge  #] [MD5                             ] Description");
    println!(
        "[Challenge 10] [{:x}] Implement CBC mode",
        md5::compute(challenge_10::solve())
    );
}

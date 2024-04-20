mod s1c3;
mod s1c4;
mod s1c6;
mod s1c7;
fn main() { 
    println!("Set 1: Basics");
    println!("----------------");
    println!("[Challenge #] [MD5                             ] Description");
    println!("[Challenge 3] [{:x}] Single-byte XOR cipher ", md5::compute(s1c3::solve()));
    println!("[Challenge 4] [{:x}] Detect single-character XOR ", md5::compute(s1c4::solve()));
    println!("[Challenge 6] [{:x}] Break repeating-key XOR", md5::compute(s1c6::solve()));

}
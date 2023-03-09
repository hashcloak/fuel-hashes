use sha2::{Sha512, Digest};
use hex;

// Testcase 1 from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
pub fn hash_abc() {
  let mut hasher = Sha512::new();
  let data = "abc";
  hasher.update(data);
  let hash1: String = format!("{:x}", hasher.finalize());
  println!("hash: {:?}", hash1); 
}

// Testcase 2 from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
pub fn hash_longer() {
  let mut hasher = Sha512::new();
  // let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  let data =  [
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
    0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
    0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
];

  hasher.update(data);
  let hash1: String = format!("{:x}", hasher.finalize());
  println!("hash: {:?}", hash1);  
}

pub fn hash_2000() {
  let mut hasher = Sha512::new();
  let data = [0x61; 2000];
  hasher.update(data);
  let hash1: String = format!("{:x}", hasher.finalize());
  println!("hash: {:?}", hash1);  
  // 6c9e0a66fecefe82816c2ecbac263c77ab18c93504a2df139e0c19535fa12b675b101894384e953652dd891d5e8d988c218dd7d8c43d493ea2b5ee27e196af6c
}

pub fn hash_longest() {
  let mut hasher = Sha512::new();
  let data = [0x61; 20000];
  hasher.update(data);
  let hash1: String = format!("{:x}", hasher.finalize());
  println!("hash: {:?}", hash1);  
  // 4ac47b5804bb5178ecdca52aeceb71341d2f1f2b3e9fc622183920fde1ef16e17bc8b6ac49819968cdf8d122c8450afd74c0d482ec4068254fb13bd50f5551bf
}

pub fn hash_hc() {
  let mut hasher = Sha512::new();
  let data = "HashCloak ".repeat(100);
  println!("{}", data.as_bytes().len());
  println!("{:?}", data.as_bytes());

  hasher.update(data);
  let hash1: String = format!("{:x}", hasher.finalize());
  println!("hash: {:?}", hash1); 
  //1d79330e2ac715a4564c13fbfadbfebfcb0e2c03991d740e18e40160613911df360c728c80ded143ba1ac629086d41fa488367e1edd69301b8af02541045cb2d
}

//cargo test -- --nocapture         
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        hash_abc();
        hash_longer();
        hash_2000();
        hash_longest();
        hash_hc();
    }
}

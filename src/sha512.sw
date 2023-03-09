library sha512;

use std::logging::log;
use std::flags::{disable_panic_on_overflow, enable_panic_on_overflow};

pub struct Block {
  b: [u64; 16]
}

pub struct Hash {
  h: [u64; 8]
}

pub const initial_hash_value: [u64; 8] = [
    0x6a09e667f3bcc908, 
    0xbb67ae8584caa73b, 
    0x3c6ef372fe94f82b, 
    0xa54ff53a5f1d36f1, 
    0x510e527fade682d1, 
    0x9b05688c2b3e6c1f, 
    0x1f83d9abfb41bd6b, 
    0x5be0cd19137e2179,
];

pub const K: [u64; 80] = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

impl Vec<u8> {
  pub fn push_vec(ref mut self, other: Vec<u8>) {
    let mut i = 0;
    while i < other.len() {
      self.push(other.get(i).unwrap());
      i += 1;
    }
  }
}

impl u64 {
  pub fn u64_to_bytes(self) -> [u8; 8] {
      let b1: u8 = ((self >> 56) & 0xFF);
      let b2: u8 = ((self >> 48) & 0xFF);
      let b3: u8 = ((self >> 40) & 0xFF);
      let b4: u8 = ((self >> 32) & 0xFF);
      let b5: u8 = ((self >> 24) & 0xFF);
      let b6: u8 = ((self >> 16) & 0xFF);
      let b7: u8 = ((self >> 8) & 0xFF);
      let b8: u8 = (self & 0xFF);
      [b1, b2, b3, b4, b5, b6, b7, b8]
  }
}

//works
pub fn get_u64(bytes: [u8;8]) -> u64 {
  (bytes[0] << 56)
    .binary_or((bytes[1] << 48))
    .binary_or((bytes[2] << 40))
    .binary_or((bytes[3] << 32))
    .binary_or((bytes[4] << 24))
    .binary_or((bytes[5] << 16))
    .binary_or((bytes[6] << 8))
    .binary_or((bytes[7]))
}

// circular rotate x by n steps to the right
// returns (x>>n) OR (x<<(w-n)
pub fn rotr_u64(x: u64, n: u8) -> u64 {
  (x >> n).binary_or(x << (64-n))
}

pub fn shr_u64(x: u64, n: u8) -> u64 {
  x >> n
}

//  (x and y) xor (not x and z)
pub fn ch(x: u64, y: u64, z: u64) -> u64 {
  (x.binary_and(y)).binary_xor((x.not()).binary_and(z))
}

// (x and y) xor (x and z) xor (y and z)
pub fn maj(x: u64, y: u64, z: u64) -> u64 {
  (x.binary_and(y)).binary_xor(x.binary_and(z)).binary_xor(y.binary_and(z))
}

// sigma_0ˆ512 = 
//    ROTRˆ1(x) xor ROTRˆ8(x) xor SHRˆ7(x)
pub fn sigma_0(x: u64) -> u64 {
  rotr_u64(x, 1).binary_xor(rotr_u64(x, 8)).binary_xor(shr_u64(x, 7))
}

// sigma_1ˆ512 =
//    ROTRˆ19(x) xor ROTRˆ61(x) xor SHRˆ6(x)
pub fn sigma_1(x: u64) -> u64 {
  rotr_u64(x, 19).binary_xor(rotr_u64(x, 61)).binary_xor(shr_u64(x, 6))
}

pub fn SIGMA_0(x: u64) -> u64 {
  rotr_u64(x, 28).binary_xor(rotr_u64(x, 34)).binary_xor(rotr_u64(x, 39))
}

pub fn SIGMA_1(x: u64) -> u64 {
  rotr_u64(x, 14).binary_xor(rotr_u64(x, 18)).binary_xor(rotr_u64(x, 41))
}

// Theoretical max message length in bytes is 18446744073709551471 (in bits 147573952589676411768)
// See explanation in README
// Practical probably around 20000 bytes
pub fn preprocessing_msg(message: Vec<u8>) -> Vec<u8> {
  let l = message.len() * 8;
  let l_reduced = l % 1024;

  // 8 because we append byte 0x80, instead of the single bit 1
  // l + 8 + k = 896 mod 1024
  // l + k = 888 mod 1024
  // k = 888 - (l mod 1024) mod 1024
  let k = if (l_reduced > 888) {
    1024 - (l_reduced - 888)
  } else {
    888 - l_reduced
  };

  let mut padded_message: Vec<u8> = Vec::new(); 
  padded_message.push_vec(message);
  padded_message.push(0x80);

  let mut i = 0;
  while i < (k/8) { // k is number in bits, but we add bytes
    padded_message.push(0u8);
    i += 1;
  }

  // According to NIST standard, message length in bits is max 128, 
  //  but Sway return vector length as u64 and thus has max length 64
  // Therefore, 64 bits will be 0. 
  i = 0;
  while i < 8 {
    padded_message.push(0u8);
    i += 1;
  }
  
  let message_len_bits:u64 = message.len() * 8;
  // Append message length in bits
  let b = message_len_bits.u64_to_bytes(); 
  padded_message.push(b[0]);
  padded_message.push(b[1]);
  padded_message.push(b[2]);
  padded_message.push(b[3]);
  padded_message.push(b[4]);
  padded_message.push(b[5]);
  padded_message.push(b[6]);
  padded_message.push(b[7]);
  padded_message
}

// padded_msg has max bitlength 147573952589676411904, which is 18446744073709551488 bytes. This last number fits in a u64
pub fn parsing(padded_msg: Vec<u8>) -> Vec<Block> {
  let mut blocks: Vec<Block> = Vec::new();
  let mut j = 0;
  while (blocks.len() * 128) < padded_msg.len() { // per iteration, 128 bytes are read
    let mut b = [0u64; 16];
    // 8 bytes together form 1 u64
    let mut word_count = 0;
    let mut i = 0;
    while i < 128 {
      let bytes = [
        padded_msg.get(i + j).unwrap(),
        padded_msg.get(i + j + 1).unwrap(),
        padded_msg.get(i + j + 2).unwrap(),
        padded_msg.get(i + j + 3).unwrap(),
        padded_msg.get(i + j + 4).unwrap(),
        padded_msg.get(i + j + 5).unwrap(),
        padded_msg.get(i + j + 6).unwrap(),
        padded_msg.get(i + j + 7).unwrap(),
      ];
      b[word_count] = get_u64(bytes);
      word_count += 1;
      i += 8;
    }
    j += 128;
    blocks.push(Block { b: b});
  }

  blocks
}

pub fn hash_msg(M: Vec<Block>) -> Hash { 
  let N = M.len();
  let mut i = 0;
  let mut current_hash_value: [u64; 8] = initial_hash_value;
  // Addition mod 2ˆ64 happens automatically if we disable panic on overflow.
  // just have to turn it on after the calculations
  disable_panic_on_overflow();

  while i < N {
    let mut ws: Vec<u64> = Vec::new();
    let mut j = 0;
    while j < 16 {
      ws.push((M.get(i).unwrap()).b[j]);
      j += 1;
    }

    while j < 80 {
      let new_val = sigma_1(ws.get(j-2).unwrap()) + ws.get(j-7).unwrap() + sigma_0(ws.get(j-15).unwrap()) + ws.get(j-16).unwrap();
      ws.push(new_val);
      j += 1;
    }
    
    let mut a = current_hash_value[0];
    let mut b = current_hash_value[1];
    let mut c = current_hash_value[2];
    let mut d = current_hash_value[3];
    let mut e = current_hash_value[4];
    let mut f = current_hash_value[5];
    let mut g = current_hash_value[6];
    let mut h = current_hash_value[7];

    let mut t = 0;
    while t < 80 {
      let T1 = h + SIGMA_1(e) + ch(e, f, g) + K[t] + ws.get(t).unwrap();
      let T2 = SIGMA_0(a) + maj(a, b, c);

      // don't know why these intermediate values are necessary, but it won't work otherwise
      let new_h = g;
      let new_g = f;
      let new_f = e;
      let new_e = d + T1;
      let new_d = c;
      let new_c = b;
      let new_b = a;
      let new_a = T1 + T2;

      a = new_a;
      b = new_b;
      c = new_c;
      d = new_d;
      e = new_e;
      f = new_f;
      g = new_g;
      h = new_h;

      t += 1;
    }

    let temp_H0 = a + current_hash_value[0];
    let temp_H1 = b + current_hash_value[1];
    let temp_H2 = c + current_hash_value[2];
    let temp_H3 = d + current_hash_value[3];
    let temp_H4 = e + current_hash_value[4];
    let temp_H5 = f + current_hash_value[5];
    let temp_H6 = g + current_hash_value[6];
    let temp_H7 = h + current_hash_value[7];
    
    current_hash_value[0] = temp_H0;
    current_hash_value[1] = temp_H1;
    current_hash_value[2] = temp_H2;
    current_hash_value[3] = temp_H3;
    current_hash_value[4] = temp_H4;
    current_hash_value[5] = temp_H5;
    current_hash_value[6] = temp_H6;
    current_hash_value[7] = temp_H7;
    
    i += 1;
  }
  enable_panic_on_overflow();

  Hash {
    h: [
      current_hash_value[0],
      current_hash_value[1],
      current_hash_value[2],
      current_hash_value[3],
      current_hash_value[4],
      current_hash_value[5],
      current_hash_value[6],
      current_hash_value[7],
    ]
  }
}

pub fn hash(msg: Vec<u8>) -> Hash {
  let mut padded_msg = preprocessing_msg(msg);
  let parsed_vec = parsing(padded_msg);
  hash_msg(parsed_vec)
}
script;
dep sha512;

use std::constants::ZERO_B256;
use sha512::*;
use std::logging::log;
use std::flags::{disable_panic_on_overflow, enable_panic_on_overflow};

fn main () {
  test_preprocessing_msg();
  test_parsing();
  test_get_u64();
  test_rotr_u64();
  test_ch();
  test_maj();
  test_additionmod_u64();

  // 2 TEST WITH VALUES ACCORDING TO https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
  test_hash_single_block();
  test_hash_two_blocks();

  // Tests with values, output confirmed in Rust
  test_hash_long_input();
  test_hash_longest_possible_input();
  test_hc_hash();
}

fn test_preprocessing_msg() {
  // length 3 and length 3 + 1024 should have the same k
  let mut message = Vec::new();
  message.push(0x61);
  message.push(0x62);
  message.push(0x63);
  let res = preprocessing_msg(message);
  // 3*8 + 1+871 = 898. This fits in 1 block of 1024 bits, which is 128 bytes
  assert(res.len() == 128);

  let mut i = 0;
  while i < 1024 { 
    message.push(0x61);
    i += 1;
  }
  let res2 = preprocessing_msg(message);
  assert(res2.len() == (128 + 1024));
}

fn test_parsing() {
  let mut message = Vec::new();
  message.push(0x61);
  message.push(0x62);
  message.push(0x63);
  let mut padded_msg = preprocessing_msg(message);
  let res = parsing(padded_msg);
  assert(res.len() == 1);

  let mut i = 0;
  while i < 1024 { 
    message.push(0x61);
    i += 1;
  }
  let padded_msg2 = preprocessing_msg(message);
  let res2 = parsing(padded_msg2);
  assert(res2.len() == 9);
}

fn test_get_u64() {
  // [0, 0, 0, 0, 0, 0, 0, 1]
  //1
  let res1 = get_u64([0, 0, 0, 0, 0, 0, 0, 1]);
  assert(res1 == 1);
  
  // [0, 0, 0, 0, 0, 0, 1, 1]
  //281474976710656
  let res1b = get_u64([0, 0, 0, 0, 0, 0, 1, 1]);  
  assert(res1b == 257);

  // [255, 255, 255, 255, 255, 255, 255, 255]
  // //18446744073709551615
  let res2 = get_u64([255, 255, 255, 255, 255, 255, 255, 255]);
  assert(res2 == 18446744073709551615);

  // Input: [1, 2, 3, 4, 5, 6, 7, 8]
  // Expected output: 578437695752307201
  let res3 = get_u64([1, 2, 3, 4, 5, 6, 7, 8]);
  assert(res3 == 72623859790382856);
}

fn test_rotr_u64() {
  assert(rotr_u64(1, 1) == 9223372036854775808);
  assert(rotr_u64(1, 10) == 18014398509481984);
  assert(rotr_u64(9223372036854775809, 1) == 13835058055282163712);
  assert(rotr_u64(100, 10) == 1801439850948198400);
}

fn test_ch() {
  // 1 and 1 = 1
  // not 1 and 1 = 0
  // 1 xor 0 = 1
  assert(ch(1,1,1) == 1);
  
  // 0 and 18446744073709551615 = 0
  // not 0 and 0 = 0
  // 0 xor 0 = 0
  assert(ch(0, 18446744073709551615, 0) == 0);

  assert(ch(17446618101274733468, 15273244494294103512, 4310090622473610715) == 15840381136804586971);

  // TESTCODE IN RUST
  /*
  fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
  }
  */
}

fn test_maj() {
  assert(maj(1,1,1) == 1);
  assert(maj(0, 18446744073709551615, 0) == 0);
  assert(maj(17446618101274733468, 15273244494294103512, 4310090622473610715) == 17569904107785889240);
  // TESTCODE IN RUST
  /*
    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }
  */
}

fn test_additionmod_u64() {
  // conclusion addition mod 2ˆ64 happens automatically, the only thing necessary is disable and enable panic on overflow
  disable_panic_on_overflow();
  let res = 18446744073709551615 + 18446744073709551615;
  assert(res == 18446744073709551614);
  assert(0 + 0 ==  0);
  assert(18446744073709551615 + 1 == 0 );
  assert(18446744073709551615 + 18446744073709551615 == 18446744073709551614);
  assert(1234567890123456789 + 9876543210987654321 == 11111111101111111110);
  assert(9223372036854775807 + 9223372036854775807 == 18446744073709551614);
  enable_panic_on_overflow();
}

fn test_hash_single_block() {
  let mut message = Vec::new();
  message.push(0x61);
  message.push(0x62);
  message.push(0x63);
  let padded_msg = preprocessing_msg(message);

  // TEST ACCORDING TO https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
  let parsed_vec = parsing(padded_msg);
  let hash_res = hash_msg(parsed_vec);
  let mut i = 0;
  // ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
  // Correct according to doc
  assert(hash_res.h[0] == 15974045371385084602);
  assert(hash_res.h[1] == 14718171817514647857);
  assert(hash_res.h[2] == 1362051152550133410);
  assert(hash_res.h[3] == 765311659573367706);
  assert(hash_res.h[4] == 2419164356178592168);
  assert(hash_res.h[5] == 3943530547489205181);
  assert(hash_res.h[6] == 4993722480620005390);
  assert(hash_res.h[7] == 3069987439919277215);
}

fn test_hash_two_blocks() {
  let mut message = Vec::new();
  message.push(0x61);
  message.push(0x62);
  message.push(0x63);
  message.push(0x64);
  message.push(0x65);
  message.push(0x66);
  message.push(0x67);
  message.push(0x68);

  message.push(0x62);
  message.push(0x63);
  message.push(0x64);
  message.push(0x65);
  message.push(0x66);
  message.push(0x67);
  message.push(0x68);
  message.push(0x69);

  message.push(0x63);
  message.push(0x64);
  message.push(0x65);
  message.push(0x66);
  message.push(0x67);
  message.push(0x68);
  message.push(0x69);
  message.push(0x6a);

  message.push(0x64);
  message.push(0x65);
  message.push(0x66);
  message.push(0x67);
  message.push(0x68);
  message.push(0x69);
  message.push(0x6a);
  message.push(0x6b);

  message.push(0x65);
  message.push(0x66);
  message.push(0x67);
  message.push(0x68);
  message.push(0x69);
  message.push(0x6a);
  message.push(0x6b);
  message.push(0x6c);

  message.push(0x66);
  message.push(0x67);
  message.push(0x68);
  message.push(0x69);
  message.push(0x6a);
  message.push(0x6b);
  message.push(0x6c);
  message.push(0x6d);

  message.push(0x67);
  message.push(0x68);
  message.push(0x69);
  message.push(0x6a);
  message.push(0x6b);
  message.push(0x6c);
  message.push(0x6d);
  message.push(0x6e);

  message.push(0x68);
  message.push(0x69);
  message.push(0x6a);
  message.push(0x6b);
  message.push(0x6c);
  message.push(0x6d);
  message.push(0x6e);
  message.push(0x6f);

  message.push(0x69);
  message.push(0x6a);
  message.push(0x6b);
  message.push(0x6c);
  message.push(0x6d);
  message.push(0x6e);
  message.push(0x6f);
  message.push(0x70);

  message.push(0x6a);
  message.push(0x6b);
  message.push(0x6c);
  message.push(0x6d);
  message.push(0x6e);
  message.push(0x6f);
  message.push(0x70);
  message.push(0x71);

  message.push(0x6b);
  message.push(0x6c);
  message.push(0x6d);
  message.push(0x6e);
  message.push(0x6f);
  message.push(0x70);
  message.push(0x71);
  message.push(0x72);

  message.push(0x6c);
  message.push(0x6d);
  message.push(0x6e);
  message.push(0x6f);
  message.push(0x70);
  message.push(0x71);
  message.push(0x72);
  message.push(0x73);

  message.push(0x6d);
  message.push(0x6e);
  message.push(0x6f);
  message.push(0x70);
  message.push(0x71);
  message.push(0x72);
  message.push(0x73);
  message.push(0x74);

  message.push(0x6e);
  message.push(0x6f);
  message.push(0x70);
  message.push(0x71);
  message.push(0x72);
  message.push(0x73);
  message.push(0x74);
  message.push(0x75);

  // TEST ACCORDING TO https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
  let mut padded_msg = preprocessing_msg(message);
  let parsed_vec = parsing(padded_msg);
  let hash_res = hash_msg(parsed_vec);

  // the hash functions does preprocessing, parsing and hashing
  let hash_again = hash(message);
  //8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909
  assert(hash_res.h[0] == 10274289055401448410);
  assert(hash_res.h[1] == 10157014811150128191);
  assert(hash_res.h[2] == 10337865364915847073);
  assert(hash_res.h[3] == 8257823452875493400);
  assert(hash_res.h[4] == 5772814957653587940);
  assert(hash_res.h[5] == 3682706302367515450);
  assert(hash_res.h[6] == 14398898538880509524);
  assert(hash_res.h[7] == 6815887267346508041);

  assert(hash_again.h[0] == 10274289055401448410);
  assert(hash_again.h[1] == 10157014811150128191);
  assert(hash_again.h[2] == 10337865364915847073);
  assert(hash_again.h[3] == 8257823452875493400);
  assert(hash_again.h[4] == 5772814957653587940);
  assert(hash_again.h[5] == 3682706302367515450);
  assert(hash_again.h[6] == 14398898538880509524);
  assert(hash_again.h[7] == 6815887267346508041);
}

fn test_hash_long_input() {
  let mut message = Vec::new();
  let mut i = 0;
  while i < 2000 { 
    message.push(0x61);
    i += 1;
  }
  let res = hash(message);
  //6c9e0a66fecefe82816c2ecbac263c77ab18c93504a2df139e0c19535fa12b675b101894384e953652dd891d5e8d988c218dd7d8c43d493ea2b5ee27e196af6c
  //Checked in Rust
  assert(res.h[0] == 7826704639894421122);
  assert(res.h[1] == 9325880380678880375);
  assert(res.h[2] == 12328825209474965267);
  assert(res.h[3] == 11388505403590519655);
  assert(res.h[4] == 6561771681957713206);
  assert(res.h[5] == 5971079440196540556);
  assert(res.h[6] == 2417825900973082942);
  assert(res.h[7] == 11724539059984838508);
}

fn test_hash_longest_possible_input() {
  let mut message = Vec::new();
  let mut i = 0;
  while i < 20000 { // max I was able to run! An extra 0 wouldn't run
    message.push(0x61);
    i += 1;
  }
  let res = hash(message);
  assert(res.h[0] == 5387566672208679288);
  assert(res.h[1] == 17067698291609399604);
  assert(res.h[2] == 2102933821600024098);
  assert(res.h[3] == 1745462605372135137);
  assert(res.h[4] == 8919579913091127656);
  assert(res.h[5] == 14841842519318530813);
  assert(res.h[6] == 8412957762702567461);
  assert(res.h[7] == 5742436786145415615);

  //4ac47b5804bb5178ecdca52aeceb71341d2f1f2b3e9fc622183920fde1ef16e17bc8b6ac49819968cdf8d122c8450afd74c0d482ec4068254fb13bd50f5551bf
  //Checked in Rust
}

fn test_hc_hash() {
  let mut message = Vec::new();
  let mut i = 0;
  while i < 100 {// "HashCloak "
    message.push(72);
    message.push(97);
    message.push(115);
    message.push(104);
    message.push(67);
    message.push(108);
    message.push(111);
    message.push(97);
    message.push(107);
    message.push(32);
    i += 1;
  }
  let res = hash(message);
  
  //1d79330e2ac715a4564c13fbfadbfebfcb0e2c03991d740e18e40160613911df360c728c80ded143ba1ac629086d41fa488367e1edd69301b8af02541045cb2d
  //Correct with Rust impl
  assert(res.h[0] == 2123784835222148516);
  assert(res.h[1] == 6218367158458252991);
  assert(res.h[2] == 14631680633338688526);
  assert(res.h[3] == 1793560065059918303);
  assert(res.h[4] == 3894613725551710531);
  assert(res.h[5] == 13410248719986409978);
  assert(res.h[6] == 5225134212735472385);
  assert(res.h[7] == 13307857983976622893);
}
# SHA2 hashes in Sway

## SHA-512

Official docs:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

Test docs:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf

A message block has 1024 bits, represented as 16 64-bit words. 

Operations on words:
- and, or , xor, not
- addition mod 2ˆ64
- rightshift SHRˆn(x), 0<=n<64: x>>n
- rotate right (circular right shift) ROTRˆn(x), 0<=n<64; (x>>n) OR (x<<(w-n))

Functions (4.1.3):
- Ch(x,y,z) =  (x and y) xor (not x and z)
- Maj(x,y,z) = (x and y) xor (x and z) xor (y and z)
- SIGMA_0(x)= ROTRˆ28(x) xor ROTRˆ34(x) xor ROTRˆ39(x)
- SIGMA_1(x) = ROTRˆ14(x) xor ROTRˆ18(x) xor ROTRˆ41(x)
- sigma_0(x) = ROTRˆ1(x) xor ROTRˆ8(x) xor SHRˆ7(x)
- sigma_1(x) = ROTRˆ19(x) xor ROTRˆ61(x) xor SHRˆ6(x)

Constants:
80 constant 64-bit words. These represent the first 64 bits of the practional parts of the cube roots of the first eighty ptime numbers. 


Notes:
$M_0ˆ(i)$ are the first 64 bits of the message block $Mˆi$. 

$M_1ˆ(i)$ the next block of 64 bits etc.

### Notes on Preprocessing of message

3 steps:
1. padding the message
2. parsing the message into blocks of 1024 bits
3. setting initial hash value

#### 1. Padding the msg

For msg M with length l bits:
- append bit 1
- append k zero bits, where k is the smallest non-negative solution to the equation l + 1 + k = 896 mod 1024
- append 128 bits expressing l as bits

#### 2. Parsing msg into blocks of 1024 bits

Parse msg + padding into blocks of 16 64-bit words (u64). 

#### 3. Set initial hash value

```rust
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
```

### SHA-512 Testing
Spin up a Fuel node

```
fuel-core --db-type in-memory

```

Run the script with tests: (`tests_sha512.sw`, can be pointed towards in Forc.toml)
```
forc run --pretty-print --unsigned
```

### Max msg length

Vec length in Sway is given with a u64. So although officially SHA-512 supports message length max 2ˆ128 bits, in this implementation *theoretically* msg length up to 147573952589676411768 bits is supported. In our testing the max msg length was 20000 bytes which is 160k bits. 

Reasoning for theoretical upper limit:

padded_msg can have length max 2ˆ64 -1 (because is represented in u64)
but we also know that padded_msg is a multiple of 1024 bits, since it has been prepared to be parsed into blocks of 1024 bits. 
padded_msg consists of bytes, so this makes a total of (2ˆ64 -1) * 8 bits.
This number is not divisible by 1024. So padded_msg can have the the largest number smaller than (2ˆ64 -1) * 8 which is a multiple of 1024. 
(2ˆ64 -1) * 8 - x = 0 mod 1024
x = 1016
(2ˆ64 -1) * 8 - 1016 = 147573952589676411904 is indeed divisble by 1024
So max length padded_msg is 147573952589676411904 bits

padded_msg = msg bit length + 128 bits + 8 bits
=>
msg max bit length = 147573952589676411904 - 128 - 8 = 147573952589676411768

### Rust code for checking

To easily add new testcases, a Rust project has been added where sha512 are generated. 
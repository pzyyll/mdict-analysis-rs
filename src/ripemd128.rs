use byteorder::{ByteOrder, LittleEndian};

const VERSION: &str = "p4.0";

fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    assert!(j < 64);
    if j < 16 {
        x ^ y ^ z
    } else if j < 32 {
        (x & y) | (z & !x)
    } else if j < 48 {
        (x | !y) ^ z
    } else {
        (x & z) | (y & !z)
    }
}

fn K(j: usize) -> u32 {
    assert!(j < 64);
    if j < 16 {
        0x00000000
    } else if j < 32 {
        0x5a827999
    } else if j < 48 {
        0x6ed9eba1
    } else {
        0x8f1bbcdc
    }
}

fn Kp(j: usize) -> u32 {
    assert!(j < 64);
    if j < 16 {
        0x50a28be6
    } else if j < 32 {
        0x5c4dd124
    } else if j < 48 {
        0x6d703ef3
    } else {
        0x00000000
    }
}

fn pad_and_split(message: &[u8]) -> Vec<Vec<u32>> {
    let origlen = message.len();
    let padlength = (64 - ((origlen + 8) % 64)) % 64; // minimum padding is 1!
    let mut padded_message = Vec::from(message);
    padded_message.push(0x80);
    padded_message.extend(vec![0x00; padlength - 1]);
    let origlen_bits = (origlen as u64) * 8;
    let mut len_bytes = [0u8; 8];
    LittleEndian::write_u64(&mut len_bytes, origlen_bits);
    padded_message.extend_from_slice(&len_bytes);
    assert!(
        padded_message.len() % 64 == 0,
        "padded_message.len() = {} != 64",
        padded_message.len()
    );

    padded_message
        .chunks(64)
        .map(|chunk| {
            chunk
                .chunks(4)
                .map(|bytes| LittleEndian::read_u32(bytes))
                .collect()
        })
        .collect()
}

fn add(args: &[u32]) -> u32 {
    args.iter().fold(0, |acc, &x| acc.wrapping_add(x))
}

fn rol(s: u32, x: u32) -> u32 {
    assert!(s < 32);
    (x << s | x >> (32 - s)) & 0xffffffff
}

const R: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2,
];

const RP: [usize; 64] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14,
];

const S: [u32; 64] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
];

const SP: [u32; 64] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
];

pub fn ripemd128(message: &[u8]) -> Vec<u8> {
    let mut h0 = 0x67452301;
    let mut h1 = 0xefcdab89;
    let mut h2 = 0x98badcfe;
    let mut h3 = 0x10325476;
    let X = pad_and_split(message);
    for i in 0..X.len() {
        let (mut A, mut B, mut C, mut D) = (h0, h1, h2, h3);
        let (mut Ap, mut Bp, mut Cp, mut Dp) = (h0, h1, h2, h3);
        for j in 0..64 {
            let T = rol(S[j], add(&[A, f(j, B, C, D), X[i][R[j]], K(j)]));
            A = D;
            D = C;
            C = B;
            B = T;
            let T = rol(SP[j], add(&[Ap, f(63 - j, Bp, Cp, Dp), X[i][RP[j]], Kp(j)]));
            Ap = Dp;
            Dp = Cp;
            Cp = Bp;
            Bp = T;
        }
        let T = add(&[h1, C, Dp]);
        h1 = add(&[h2, D, Ap]);
        h2 = add(&[h3, A, Bp]);
        h3 = add(&[h0, B, Cp]);
        h0 = T;
    }

    let mut result = vec![0u8; 16];
    LittleEndian::write_u32_into(&[h0, h1, h2, h3], &mut result);
    result
}

pub fn hexstr(bstr: &[u8]) -> String {
    bstr.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let message = b"The quick brown fox jumps over the lazy dog";
    let digest = ripemd128(message);
    assert_eq!(hexstr(&digest), "3fa9b57f053c053fbe2735b2380db596");
    println!("Digest: {}", hexstr(&digest));
    println!("f: {}", f(5, 22, 34, 35));
    println!("K: {}", K(5));
    println!("Kp: {}", Kp(5));
    println!("pad_and_split: {:?}", pad_and_split(message));
}


// Main SHA-512 function
// Input: string
// Output length: 128 hex characters (512 bits)
function sha512(message) {
    var msgBytes = utf8ToBytes(message);
    var hashBytes = sha512Compute(msgBytes);
    return bytesToHex(hashBytes);
}

// Constant
var _K = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
];

// Internal SHA-512 calculation
// Input: byte array
// Output: byte array (64 bytes)
function sha512Compute(dataBytes) {
    // Initial state
    var H = [
        [0x6a09e667, 0xf3bcc908], [0xbb67ae85, 0x84caa73b], [0x3c6ef372, 0xfe94f82b], [0xa54ff53a, 0x5f1d36f1],
        [0x510e527f, 0xade682d1], [0x9b05688c, 0x2b3e6c1f], [0x1f83d9ab, 0xfb41bd6b], [0x5be0cd19, 0x137e2179]
    ];

    var bytes = dataBytes.slice(0);
    var bitLen = bytes.length * 8;

    // Append '1' bit (0x80), then zeros, then length (as padding)
    bytes.push(0x80);
    while ((bytes.length % 128) !== 112) {
        bytes.push(0);
    }

    // Append Length (128-bit big endian). JS safe limit uses low 64 bits mostly.
    bytes.push(0, 0, 0, 0, 0, 0, 0, 0); // High 64-bits
    var hiLen = (bitLen / 0x100000000) >>> 0;
    var loLen = bitLen >>> 0;
    bytes.push((hiLen >>> 24) & 0xff, (hiLen >>> 16) & 0xff, (hiLen >>> 8) & 0xff, hiLen & 0xff);
    bytes.push((loLen >>> 24) & 0xff, (loLen >>> 16) & 0xff, (loLen >>> 8) & 0xff, loLen & 0xff);

    var W = new Array(80);

    for (var off = 0; off < bytes.length; off += 128) {
        var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

        for (var i = 0; i < 80; i++) {
            if (i < 16) {
                var p = off + i * 8;
                W[i] = [
                    ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | (bytes[p + 3])) >>> 0,
                    ((bytes[p + 4] << 24) | (bytes[p + 5] << 16) | (bytes[p + 6] << 8) | (bytes[p + 7])) >>> 0
                ];
            } else {
                var s0 = rotr64(W[i - 15][0], W[i - 15][1], 1);
                var s0b = rotr64(W[i - 15][0], W[i - 15][1], 8);
                var s0c = shr64(W[i - 15][0], W[i - 15][1], 7);
                var S0 = [s0[0] ^ s0b[0] ^ s0c[0], s0[1] ^ s0b[1] ^ s0c[1]];

                var s1 = rotr64(W[i - 2][0], W[i - 2][1], 19);
                var s1b = rotr64(W[i - 2][0], W[i - 2][1], 61);
                var s1c = shr64(W[i - 2][0], W[i - 2][1], 6);
                var S1 = [s1[0] ^ s1b[0] ^ s1c[0], s1[1] ^ s1b[1] ^ s1c[1]];

                var tA = add64(W[i - 16][0], W[i - 16][1], S0[0], S0[1]);
                var tB = add64(W[i - 7][0], W[i - 7][1], S1[0], S1[1]);
                W[i] = add64(tA[0], tA[1], tB[0], tB[1]);
            }

            var r1a = rotr64(e[0], e[1], 14);
            var r1b = rotr64(e[0], e[1], 18);
            var r1c = rotr64(e[0], e[1], 41);
            var Sigma1 = [r1a[0] ^ r1b[0] ^ r1c[0], r1a[1] ^ r1b[1] ^ r1c[1]];

            var Ch = [(e[0] & f[0]) ^ (~e[0] & g[0]), (e[1] & f[1]) ^ (~e[1] & g[1])];

            var temp1 = add64(h[0], h[1], Sigma1[0], Sigma1[1]);
            temp1 = add64(temp1[0], temp1[1], Ch[0], Ch[1]);
            temp1 = add64(temp1[0], temp1[1], _K[i * 2], _K[i * 2 + 1]);
            temp1 = add64(temp1[0], temp1[1], W[i][0], W[i][1]);

            var r0a = rotr64(a[0], a[1], 28);
            var r0b = rotr64(a[0], a[1], 34);
            var r0c = rotr64(a[0], a[1], 39);
            var Sigma0 = [r0a[0] ^ r0b[0] ^ r0c[0], r0a[1] ^ r0b[1] ^ r0c[1]];

            var Maj = [(a[0] & b[0]) ^ (a[0] & c[0]) ^ (b[0] & c[0]), (a[1] & b[1]) ^ (a[1] & c[1]) ^ (b[1] & c[1])];

            var temp2 = add64(Sigma0[0], Sigma0[1], Maj[0], Maj[1]);

            h = g; g = f; f = e;
            e = add64(d[0], d[1], temp1[0], temp1[1]);
            d = c; c = b; b = a;
            a = add64(temp1[0], temp1[1], temp2[0], temp2[1]);
        }

        H[0] = add64(H[0][0], H[0][1], a[0], a[1]);
        H[1] = add64(H[1][0], H[1][1], b[0], b[1]);
        H[2] = add64(H[2][0], H[2][1], c[0], c[1]);
        H[3] = add64(H[3][0], H[3][1], d[0], d[1]);
        H[4] = add64(H[4][0], H[4][1], e[0], e[1]);
        H[5] = add64(H[5][0], H[5][1], f[0], f[1]);
        H[6] = add64(H[6][0], H[6][1], g[0], g[1]);
        H[7] = add64(H[7][0], H[7][1], h[0], h[1]);
    }

    var out = [];
    for (var k = 0; k < 8; k++) {
        out.push((H[k][0] >>> 24) & 0xff, (H[k][0] >>> 16) & 0xff, (H[k][0] >>> 8) & 0xff, H[k][0] & 0xff);
        out.push((H[k][1] >>> 24) & 0xff, (H[k][1] >>> 16) & 0xff, (H[k][1] >>> 8) & 0xff, H[k][1] & 0xff);
    }

    return out;
}

// UTF-8 encoding
function utf8ToBytes(str) {
    // If str is already an array, assume it's bytes and return it
    if (Array.isArray(str) || (str && str.length && typeof str[0] === 'number')) {
        return str;
    }

    var arr = [], i = 0, c;
    while (i < str.length) {
        c = str.charCodeAt(i++);
        if (c >= 0xD800 && c <= 0xDBFF && i < str.length) {
            var c2 = str.charCodeAt(i);
            if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                i++;
                c = 0x10000 + (((c & 0x3FF) << 10) | (c2 & 0x3FF));
            }
        }
        
        if (c < 0x80) arr.push(c);
        else if (c < 0x800) {
            arr.push(0xC0 | (c >>> 6));
            arr.push(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            arr.push(0xE0 | (c >>> 12));
            arr.push(0x80 | ((c >>> 6) & 0x3F));
            arr.push(0x80 | (c & 0x3F));
        } else {
            arr.push(0xF0 | (c >>> 18));
            arr.push(0x80 | ((c >>> 12) & 0x3F));
            arr.push(0x80 | ((c >>> 6) & 0x3F));
            arr.push(0x80 | (c & 0x3F));
        }
    }

    return arr;
}

// Convert byte array to hex string
// Input: byte array
// Output: hex string
function bytesToHex(bytes) {
    var hex = "", b;
    for (var i = 0; i < bytes.length; i++) {
        b = bytes[i];
        hex += (b < 16 ? "0" : "") + b.toString(16);
    }

    return hex;
}


// 64 bit helpers

// 64-bit addition (hi, lo)
function add64(aHi, aLo, bHi, bLo) {
    aHi >>>= 0; aLo >>>= 0;
    bHi >>>= 0; bLo >>>= 0;
    var lo = (aLo + bLo) >>> 0;
    var carry = (lo < aLo) ? 1 : 0;

    return [(aHi + bHi + carry) >>> 0, lo];
}

// 64-bit right rotate
function rotr64(hi, lo, n) {
    if (n === 32) return [lo, hi];
    if (n < 32) return [((hi >>> n) | (lo << (32 - n))) >>> 0, ((lo >>> n) | (hi << (32 - n))) >>> 0];
    n -= 32;

    return [((lo >>> n) | (hi << (32 - n))) >>> 0, ((hi >>> n) | (lo << (32 - n))) >>> 0];
}

// 64-bit right shift
function shr64(hi, lo, n) {
    if (n < 32) return [(hi >>> n) >>> 0, ((lo >>> n) | (hi << (32 - n))) >>> 0];
    return [0, (hi >>> (n - 32)) >>> 0];
}

log(`sha512 = ${sha512("message")}`);

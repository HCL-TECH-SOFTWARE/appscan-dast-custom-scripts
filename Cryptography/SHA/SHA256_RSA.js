/**
 * SHA-256 cryptographic hash function
 * @param {string} message - Input message to hash
 * @returns {string} Hexadecimal SHA-256 hash
 *
 * Parameter documentation:
 *   w: Message schedule array of 32-bit words
 *   k: Array of 64 constant 32-bit words
 *   H: Array of 8 initial hash values
 *   a-h: Working variables, initialized from H and updated each round
 *   s0, s1: Temporary variables for SHA-256 sigma functions
 *   Ch: Choose function
 *   Maj: Majority function
 *   temp1, temp2: Temporary variables for round calculations
 */
function Sha256(message) {

    /**
     * Right rotate (circular right shift) operation, where x is a w-bit word and n is an integer with 0 <= n < w
     * @param {number} value - 32-bit word
     * @param {number} amount - Number of bits to rotate
     * @returns {number} value of x rotated right by n positions
     */
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    let len = message.length * 8;
    let source = message.split('').map(c => c.charCodeAt(0));

    source[len >> 3] = 0x80;
    while ((source.length * 8 + 64) % 512 !== 0) {
        source.push(0);
    }
    
    const tmpLen = len; 
    source.push((tmpLen >>> 24) & 0xFF, (tmpLen >>> 16) & 0xFF, (tmpLen >>> 8) & 0xFF, tmpLen & 0xFF);

    // Add 4 bytes of zeros for the upper 32 bits of length
    source.splice(source.length - 4, 0, 0, 0, 0, 0);
    
    // Message schedule array of 32-bit words
    const w = new Array(64);

    // k: Array of 64 constant 32-bit words
    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // H: Initial hash value array
    let H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    for (let i = 0; i < source.length; i += 64) {
        const chunk = source.slice(i, i + 64);
        // a-h: Working variables
        let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], hh = H[7];
        for (let j = 0; j < 64; j++) {
            if (j < 16) {
                // Prepare the message schedule
                w[j] = (chunk[j * 4] << 24) | (chunk[j * 4 + 1] << 16) | (chunk[j * 4 + 2] << 8) | chunk[j * 4 + 3];
            } else {
                // s0, s1: SHA-256 sigma functions
                const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
            }

            // s1: SHA-256 Sigma1 function
            const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            // Ch: Choose function
            const Ch = (e & f) ^ (~e & g);
            // temp1: Temporary variable
            const temp1 = (hh + s1 + Ch + k[j] + w[j]) | 0;
            // s0: SHA-256 Sigma0 function
            const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            // Maj: Majority function
            const Maj = (a & b) ^ (a & c) ^ (b & c);
            // temp2: Temporary variable
            const temp2 = (s0 + Maj) | 0;

            // Update working variables
            hh = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
        }

        H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + hh) | 0;
    }

    return H.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
}


/**
 * Computes an RSA digital signature using SHA-256 and PKCS#1 v1.5 padding
 * @param {string} message - The input message to sign
 * @param {string} privateExponentHex - RSA private exponent as a hexadecimal string
 * @param {string} modulusHex - RSA modulus as a hexadecimal string
 * @returns {string} Signature as a hexadecimal string
 *
 * Steps:
 *   1. Hashes the message using SHA-256
 *   2. Applies PKCS#1 v1.5 padding for SHA-256
 *   3. Computes the signature using modular exponentiation: signature = paddedHash^d mod n
 */
function Sha256RSA(message, privateExponentHex, modulusHex) {
    
    // Helper to convert hex string to BigInt
    const hexToBigInt = hex => BigInt('0x' + hex);
    
    // Modular Exponentiation: (base^exp) mod mod
    const modPow = (base, exp, mod) => {
        let res = 1n;
        base = base % mod;
        if (base === 0n) return 0n;
        while (exp > 0n) {
            if (exp % 2n === 1n) res = (res * base) % mod;
            exp = exp / 2n;
            base = (base * base) % mod;
        }

        return res;
    };

    // PKCS#1 v1.5 Padding for SHA-256
    const pkcs1Pad = (hashHex, keySizeBytes) => {
        const asn1Header = "3031300d060960864801650304020105000420";
        const t = asn1Header + hashHex;
        
        const tLenBytes = t.length / 2;
        const psLen = keySizeBytes - tLenBytes - 3;
        
        if (psLen < 8) throw new Error("Key too short for SHA256");

        let ps = "";
        for(let i = 0; i < psLen; i++) ps += "ff";

        return "0001" + ps + "00" + t;
    };


    const hash = Sha256(message);
    
    const d = hexToBigInt(privateExponentHex);
    const n = hexToBigInt(modulusHex);
    const keySizeBytes = modulusHex.length / 2; 

    // Add padding
    const paddedHex = pkcs1Pad(hash, keySizeBytes);
    const paddedInt = hexToBigInt(paddedHex);

    // Calculate Signature
    const signatureInt = modPow(paddedInt, d, n);

    let sigHex = signatureInt.toString(16);
    while (sigHex.length < modulusHex.length) {
        sigHex = "0" + sigHex;
    }
    
    return sigHex;
}

// Example usage
const modulusHex = "bcb6d6136212f1c1bcb410712fe1e604c7fb1b00b5cc54e2d94ecca0ae8cfa8425780356dc88813cceee2ad535baf3d19d86ef1a5d90cc85844ee47afbd44ded";
const privateExponentHex = "29b5ab892b330eb60854301224482483c8038b0b54232e5bd935de6a614a0d90483a383a36f28ce1a0b77176a2e0251193aebe788e3bd771ab2cfde3291ddde1";
const myMsg = "Hello js";

const hex2 = Sha256RSA(myMsg, myPrivKey, myModulus);
log("SHA-256 RSA Signature: " + hex2);
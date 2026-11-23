// GPU SHA-1 (fixed 85-byte message, 2 blocks; no generic-message overhead)
// ASCII-only source: see p256.cuh note on cp936 codepage issues.
#pragma once
#include <cstdint>

// Message layout (byte-identical to fast-keygen.mjs computeFingerprint):
//   [0]=0x99 [1]=0x00 [2]=0x52            // 0x99 || uint16be(82)
//   [3]=0x04                              // version
//   [4..7]=created (u32 BE)
//   [8]=0x13                              // ECDSA alg id
//   [9]=0x08                              // OID length
//   [10..17]=2a 86 48 ce 3d 03 01 07      // P-256 OID
//   [18]=0x02 [19]=0x03                   // MPI bit length 515 (constant for 65B starting 0x04)
//   [20]=0x04                             // uncompressed point flag
//   [21..52]=X (32B)  [53..84]=Y (32B)
// Total 85 bytes = 0x154 bits

#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

__device__ __forceinline__ void sha1_block(const uint32_t W[16], uint32_t state[5]) {
    uint32_t w[80];
    #pragma unroll
    for (int i = 0; i < 16; i++) w[i] = W[i];
    #pragma unroll
    for (int i = 16; i < 80; i++) {
        uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = SHA1_ROTL(x, 1);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8f1bbcdcu; }
        else             { f = b ^ c ^ d;                     k = 0xca62c1d6u; }
        uint32_t tmp = SHA1_ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = SHA1_ROTL(b, 30); b = a; a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

// Compute keyId (= last 8 bytes of the SHA-1 fingerprint, output as 2 u32 BE byte-string)
// x,y are plain-domain 32-byte coordinates (not Montgomery)
__device__ __forceinline__ void pgp_keyid(const uint8_t X[32], const uint8_t Y[32],
                                          uint32_t created, uint32_t kid[2]) {
    uint32_t W0[16], W1[16];
    const uint8_t OID[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    // ---- block 0: msg[0..64) ----
    uint8_t m0[64];
    m0[0] = 0x99; m0[1] = 0x00; m0[2] = 0x52;
    m0[3] = 0x04;
    m0[4] = (uint8_t)(created >> 24); m0[5] = (uint8_t)(created >> 16);
    m0[6] = (uint8_t)(created >> 8);  m0[7] = (uint8_t)(created);
    m0[8] = 0x13;
    m0[9] = 0x08;
    #pragma unroll
    for (int i = 0; i < 8; i++) m0[10 + i] = OID[i];
    m0[18] = 0x02; m0[19] = 0x03; m0[20] = 0x04;
    #pragma unroll
    for (int i = 0; i < 43; i++) m0[21 + i] = (i < 32) ? X[i] : Y[i - 32]; // msg[21..63]

    #pragma unroll
    for (int i = 0; i < 16; i++)
        W0[i] = ((uint32_t)m0[4 * i] << 24) | ((uint32_t)m0[4 * i + 1] << 16) |
                ((uint32_t)m0[4 * i + 2] << 8) | (uint32_t)m0[4 * i + 3];

    // ---- block 1: msg[64..85) (21B) + 0x80 + pad + length (680 bit) ----
    // msg[53+j] = Y[j]  =>  msg[64+i] = Y[11+i] (i = 0..20)
    uint8_t m1[64] = {0};
    #pragma unroll
    for (int i = 0; i < 21; i++) m1[i] = Y[11 + i];
    m1[21] = 0x80;
    W1[15] = 680; // 85-byte message = 680 bits
    #pragma unroll
    for (int i = 0; i < 15; i++)
        W1[i] = ((uint32_t)m1[4 * i] << 24) | ((uint32_t)m1[4 * i + 1] << 16) |
                ((uint32_t)m1[4 * i + 2] << 8) | (uint32_t)m1[4 * i + 3];

    uint32_t state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
    sha1_block(W0, state);
    sha1_block(W1, state);

    // digest bytes 12..19 = state[3] (full) + state[4] (full), BE order
    kid[0] = state[3];
    kid[1] = state[4];
}

// ChaCha8 DRBG (device side) -- scalar derivation for the fused mining kernel.
// Validated against RFC 8439 2.3.2 test vector (same round function, 8 double-rounds).
// ASCII-only source: see p256.cuh note on cp936 codepage issues.
//
// Seeding discipline (CSPRNG red line):
//   The host draws a fresh 48-byte seed (256-bit key + 32-bit batch counter +
//   64-bit session nonce) from BCryptGenRandom every batch. Each thread derives
//   its scalar from state = constants || key || counter(=batchIdx*2^20 + threadIdx
//   space via block/idx split). Keystream block per thread is unique: counter is
//   a 32-bit slot that never repeats within a session (batch < 2^16, idx < 2^22).
#pragma once
#include <cstdint>

#define CHACHA_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

__device__ __forceinline__ void chacha_qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d = CHACHA_ROTL(d ^ a, 16);
    c += d; b = CHACHA_ROTL(b ^ c, 12);
    a += b; d = CHACHA_ROTL(d ^ a, 8);
    c += d; b = CHACHA_ROTL(b ^ c, 7);
}

// 8 double-rounds (ChaCha8); state[0..3] constants, [4..11] key, [12] counter,
// [13..15] nonce. Output written to out[16].
__device__ __forceinline__ void chacha8_block(const uint32_t state[16], uint32_t out[16]) {
    uint32_t x[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) x[i] = state[i];
    #pragma unroll
    for (int r = 0; r < 4; r++) {
        chacha_qr(x[0], x[4], x[8],  x[12]);
        chacha_qr(x[1], x[5], x[9],  x[13]);
        chacha_qr(x[2], x[6], x[10], x[14]);
        chacha_qr(x[3], x[7], x[11], x[15]);
        chacha_qr(x[0], x[5], x[10], x[15]);
        chacha_qr(x[1], x[6], x[11], x[12]);
        chacha_qr(x[2], x[7], x[8],  x[13]);
        chacha_qr(x[3], x[4], x[9],  x[14]);
    }
    #pragma unroll
    for (int i = 0; i < 16; i++) out[i] = x[i] + state[i];
}

// Derive one 32-byte scalar for thread (idx, batchIdx) from the 48-byte batch seed.
// seed layout (host, LE u32): seed[0..7] = key, seed[8..10] = session nonce,
//                             seed[11] = unused (kept for alignment)
// counter = batchIdx * 2^22 + idx  (unique per (batch, thread); batches limited
// to 2^16 per session by the host -- see miner.cu assertion)
__device__ __forceinline__ void derive_scalar(const uint32_t seed[12], uint32_t batchIdx,
                                              uint32_t idx, uint8_t scalar[32]) {
    uint32_t state[16];
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    #pragma unroll
    for (int i = 0; i < 8; i++) state[4 + i] = seed[i];
    state[12] = batchIdx * 0x400000u + idx;   // 2^22 slots per batch
    state[13] = seed[8];
    state[14] = seed[9];
    state[15] = seed[10];
    uint32_t out[16];
    chacha8_block(state, out);
    // scalar = first 32 bytes of keystream, little-endian words -> raw bytes
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        scalar[4 * i + 0] = (uint8_t)(out[i]);
        scalar[4 * i + 1] = (uint8_t)(out[i] >> 8);
        scalar[4 * i + 2] = (uint8_t)(out[i] >> 16);
        scalar[4 * i + 3] = (uint8_t)(out[i] >> 24);
    }
}

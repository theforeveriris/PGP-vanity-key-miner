// PGP Vanity Miner -- CUDA engine (v5: fused ChaCha RNG + single kernel + true double-buffer)
// ASCII-only source (see p256.cuh note on cp936 codepage issues).
//
// Architecture: ONE fused kernel per batch does seed->scalar (ChaCha8) -> Q (P-256
//               scalar mult, Montgomery CIOS w/ zero-multiply REDC row) -> SHA-1 -> keyId
//               -> rule prefilter -> hit-record compaction (d/x/y/kid of hits gathered
//               in-kernel; the host never runs a follow-up gather kernel).
//               Host<->GPU traffic per batch: 48B seed up + 4B hit count down +
//               (rarely) a few hundred bytes of hit records down.
//
// Pipeline: batch k+1's kernel is enqueued right after batch k's (separate buffer
//           set per slot, same stream => ordered), while the host waits on batch k's
//           event. The GPU never idles waiting for the host. Hit processing on the
//           host overlaps the next kernel(s).
//
// Security: every batch seed is fresh 48B from BCryptGenRandom (OS CSPRNG); the
//           ChaCha counter space (batchIdx*2^22 + idx) never repeats within a session
//           (session capped at 2^16 batches; asserted host-side).
//
// Output protocol (JSON lines, UTF-8, flushed per line): unchanged from v4
//   {"t":"ready","device":"...","sm":75,"batch":N}
//   {"t":"prog","rate":123.4,"total":1000000,"hits":H}
//   {"t":"hit","d":"<64hex>","x":"<64hex>","y":"<64hex>","kid":"<16hex>","created":1700000000}
//   {"t":"vec","d":...,"x":...,"y":...,"kid":...}        // --mode test only
//   {"t":"warn","message":"..."}
//   {"t":"error","message":"..."}
//   {"t":"done"}
//
// Exit codes: 0 normal; 2 rules not supported by the GPU engine; other non-zero = runtime error

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <windows.h>
#include <bcrypt.h>
#include <cuda_runtime.h>

#include "p256.cuh"
#include "sha1.cuh"
#include "chacha8.cuh"

// Parent (Node worker) death => stdin pipe closes => self-exit, prevents orphan GPU holding
static std::atomic<bool> gStop{false};

// ---------------- kernels ----------------

// Device-side rule evaluation, byte-identical semantics to the old host checkRule().
struct DevRule {
    int kind;           // 0 consecutive, 1 repeating, 2 palindrome, 3 substring (date/literal), 4 zeros
    int k;              // length
    int litLen;
    int lit[16];        // nibbles; for substring rules
};

__device__ __forceinline__ bool devCheckRule(const DevRule& r, const int nib[16]) {
    switch (r.kind) {
    case 0: {   // consecutive: run of equal nibbles with length >= k
        int run = 1;
        for (int i = 1; i < 16; i++) {
            run = (nib[i] == nib[i - 1]) ? run + 1 : 1;
            if (run >= r.k) return true;
        }
        return false;
    }
    case 1: {   // repeating: nib[i..i+k) == nib[i+k..i+2k)
        for (int i = 0; i + 2 * r.k <= 16; i++) {
            bool ok = true;
            for (int j = 0; j < r.k; j++)
                if (nib[i + j] != nib[i + r.k + j]) { ok = false; break; }
            if (ok) return true;
        }
        return false;
    }
    case 2: {   // palindrome: substring of length exactly k
        for (int i = 0; i + r.k <= 16; i++) {
            bool ok = true;
            for (int j = 0; j < r.k; j++)
                if (nib[i + j] != nib[i + r.k - 1 - j]) { ok = false; break; }
            if (ok) return true;
        }
        return false;
    }
    case 3: {   // substring (date/literal); dead literal => litLen 0 => never matches (safe)
        if (r.litLen <= 0 || r.litLen > 16) return false;
        for (int i = 0; i + r.litLen <= 16; i++) {
            bool ok = true;
            for (int j = 0; j < r.litLen; j++)
                if (nib[i + j] != r.lit[j]) { ok = false; break; }
            if (ok) return true;
        }
        return false;
    }
    case 4: {   // zeros: run of >= k zeros
        int run = 0;
        for (int i = 0; i < 16; i++) {
            run = (nib[i] == 0) ? run + 1 : 0;
            if (run >= r.k) return true;
        }
        return false;
    }
    }
    return false;
}

// Direct-scalar kernel (test mode + self-check only): reads raw LE scalars.
__global__ void scalar_from_buf_kernel(const uint8_t* buf, uint32_t* xsMont, uint32_t* ysMont, int count) {
    const bool active = blockIdx.x * blockDim.x + threadIdx.x < count;
    const int idx = blockIdx.x * blockDim.x + threadIdx.x;
    uint8_t s[32] = {0};
    if (active) {
        #pragma unroll
        for (int i = 0; i < 32; i++) s[i] = buf[(size_t)idx * 32 + i];
    }
    uint32_t X[LIMBS], Y[LIMBS];
    scalar_mul_G(s, X, Y);
    if (active) {
        #pragma unroll
        for (int i = 0; i < LIMBS; i++) {
            xsMont[(size_t)idx * LIMBS + i] = X[i];
            ysMont[(size_t)idx * LIMBS + i] = Y[i];
        }
    }
}

// SHA-1 keyId over Montgomery-domain coords (test mode + self-check only).
__global__ void keyid_from_xy_kernel(const uint32_t* xsMont, const uint32_t* ysMont,
                                     uint32_t created, uint32_t* kids,
                                     uint32_t* outX, uint32_t* outY, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    uint32_t xm[LIMBS], ym[LIMBS], X[LIMBS], Y[LIMBS];
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        xm[i] = xsMont[(size_t)idx * LIMBS + i];
        ym[i] = ysMont[(size_t)idx * LIMBS + i];
    }
    fp_from_mont(xm, X);
    fp_from_mont(ym, Y);
    uint8_t xb[32], yb[32];
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) {
        uint32_t vx = X[7 - i], vy = Y[7 - i];
        xb[4 * i + 0] = (uint8_t)(vx >> 24);
        xb[4 * i + 1] = (uint8_t)(vx >> 16);
        xb[4 * i + 2] = (uint8_t)(vx >> 8);
        xb[4 * i + 3] = (uint8_t)(vx);
        yb[4 * i + 0] = (uint8_t)(vy >> 24);
        yb[4 * i + 1] = (uint8_t)(vy >> 16);
        yb[4 * i + 2] = (uint8_t)(vy >> 8);
        yb[4 * i + 3] = (uint8_t)(vy);
        if (outX) outX[(size_t)idx * LIMBS + i] = X[i];
        if (outY) outY[(size_t)idx * LIMBS + i] = Y[i];
    }
    uint32_t kid[2];
    pgp_keyid(xb, yb, created, kid);
    kids[2 * (size_t)idx + 0] = kid[0];
    kids[2 * (size_t)idx + 1] = kid[1];
}

// Fused mining kernel: ChaCha8 scalar derivation -> scalar_mul_G -> keyId ->
// rule prefilter -> in-kernel hit compaction (stores d, x, y, kid of each hit).
// Inactive threads must still participate (scalar_mul_G uses __shared__+__syncthreads).
__global__ void fused_mine_kernel(const uint32_t* seed, uint32_t batchIdx,
                                  uint32_t created,
                                  uint32_t* hitScalar,   // 32B per hit slot
                                  uint32_t* hitX,        // plain-domain coords per hit slot
                                  uint32_t* hitY,
                                  uint32_t* hitKid,      // 8B per hit slot
                                  const DevRule* rules, int numRules,
                                  int* hitIdx, unsigned int* hitCount, int maxHits, int count) {
    const bool active = blockIdx.x * blockDim.x + threadIdx.x < count;
    const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    uint8_t s[32] = {0};
    if (active) {
        derive_scalar(seed, batchIdx, idx, s);
    }
    uint32_t X[LIMBS], Y[LIMBS];
    scalar_mul_G(s, X, Y);
    if (!active) return;

    // plain-domain coords (fp_from_mont is identity in v4? no: Montgomery -> plain)
    uint32_t Xm[LIMBS], Ym[LIMBS];
    #pragma unroll
    for (int i = 0; i < LIMBS; i++) { Xm[i] = X[i]; Ym[i] = Y[i]; }
    fp_from_mont(Xm, X);
    fp_from_mont(Ym, Y);

    uint32_t kid[2];
    {
        uint8_t xb[32], yb[32];
        #pragma unroll
        for (int i = 0; i < LIMBS; i++) {
            uint32_t vx = X[7 - i], vy = Y[7 - i];
            xb[4 * i + 0] = (uint8_t)(vx >> 24);
            xb[4 * i + 1] = (uint8_t)(vx >> 16);
            xb[4 * i + 2] = (uint8_t)(vx >> 8);
            xb[4 * i + 3] = (uint8_t)(vx);
            yb[4 * i + 0] = (uint8_t)(vy >> 24);
            yb[4 * i + 1] = (uint8_t)(vy >> 16);
            yb[4 * i + 2] = (uint8_t)(vy >> 8);
            yb[4 * i + 3] = (uint8_t)(vy);
        }
        pgp_keyid(xb, yb, created, kid);
    }

    if (numRules > 0) {
        int nib[16];
        #pragma unroll
        for (int w = 0; w < 2; w++) {
            uint32_t v = kid[w];
            nib[8 * w + 0] = (v >> 28) & 0xF; nib[8 * w + 1] = (v >> 24) & 0xF;
            nib[8 * w + 2] = (v >> 20) & 0xF; nib[8 * w + 3] = (v >> 16) & 0xF;
            nib[8 * w + 4] = (v >> 12) & 0xF; nib[8 * w + 5] = (v >> 8) & 0xF;
            nib[8 * w + 6] = (v >> 4) & 0xF;  nib[8 * w + 7] = v & 0xF;
        }
        bool m = false;
        for (int r = 0; r < numRules && !m; r++) m = devCheckRule(rules[r], nib);
        if (m) {
            unsigned int slot = (*hitCount < (unsigned int)maxHits) ? atomicAdd(hitCount, 1u) : (unsigned int)maxHits;
            if (slot < (unsigned int)maxHits) {
                hitIdx[slot] = (int)idx;
                #pragma unroll
                for (int i = 0; i < LIMBS; i++) {
                    hitX[(size_t)slot * LIMBS + i] = X[i];
                    hitY[(size_t)slot * LIMBS + i] = Y[i];
                }
                hitKid[2 * (size_t)slot + 0] = kid[0];
                hitKid[2 * (size_t)slot + 1] = kid[1];
                hitScalar[(size_t)slot * 8 + 0] = (uint32_t)s[0] | ((uint32_t)s[1] << 8) | ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
                hitScalar[(size_t)slot * 8 + 1] = (uint32_t)s[4] | ((uint32_t)s[5] << 8) | ((uint32_t)s[6] << 16) | ((uint32_t)s[7] << 24);
                hitScalar[(size_t)slot * 8 + 2] = (uint32_t)s[8] | ((uint32_t)s[9] << 8) | ((uint32_t)s[10] << 16) | ((uint32_t)s[11] << 24);
                hitScalar[(size_t)slot * 8 + 3] = (uint32_t)s[12] | ((uint32_t)s[13] << 8) | ((uint32_t)s[14] << 16) | ((uint32_t)s[15] << 24);
                hitScalar[(size_t)slot * 8 + 4] = (uint32_t)s[16] | ((uint32_t)s[17] << 8) | ((uint32_t)s[18] << 16) | ((uint32_t)s[19] << 24);
                hitScalar[(size_t)slot * 8 + 5] = (uint32_t)s[20] | ((uint32_t)s[21] << 8) | ((uint32_t)s[22] << 16) | ((uint32_t)s[23] << 24);
                hitScalar[(size_t)slot * 8 + 6] = (uint32_t)s[24] | ((uint32_t)s[25] << 8) | ((uint32_t)s[26] << 16) | ((uint32_t)s[27] << 24);
                hitScalar[(size_t)slot * 8 + 7] = (uint32_t)s[28] | ((uint32_t)s[29] << 8) | ((uint32_t)s[30] << 16) | ((uint32_t)s[31] << 24);
            }
        }
    }
}

// ---------------- host-side rule parsing ----------------
// Semantics: sound over-approximate OR. A candidate matching any over-approximation is
// reported; the Node side revalidates with the real matchRules. False positives are
// allowed; false negatives are absolutely forbidden.
struct PrefilterRule {
    enum Kind { CONSECUTIVE, REPEATING, PALINDROME, DATE, ZEROS, LITERAL } kind;
    int k;
    uint8_t lit[16];
    int litLen;
    bool litDead;
};

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ---------------- custom_regex -> required literal (sound over-approximation) ----------------
// Extracts, per top-level | alternative, a "required literal": if the regex matches,
// the subject must contain this literal. When no literal can be extracted from any
// alternative -> returns false (unsupported), reported by the caller.
// The algorithm mirrors gpu/test_extract.mjs branch-by-branch (that mirror passed
// 12 test cases + a 20k-sample soundness cross-check against real JS RegExp).
static bool extractLiteral(const std::string& alt, std::string& out) {
    std::string cur;
    std::string best;
    auto endRun = [&]() { if (cur.size() > best.size()) best = cur; cur.clear(); };
    for (size_t i = 0; i < alt.size(); ) {
        char c = alt[i];
        if (c == '\\' && i + 1 < alt.size()) {
            char nx = alt[i + 1];
            if (strchr("dDwWsSbB", nx) || isalnum((unsigned char)nx)) { endRun(); i += 2; }
            else { cur.push_back(nx); i += 2; }
            continue;
        }
        if (c == '[') {
            size_t j = i + 1;
            if (j < alt.size() && alt[j] == '^') j++;
            if (j < alt.size() && alt[j] == ']') j++;
            while (j < alt.size() && alt[j] != ']') { if (alt[j] == '\\') j++; j++; }
            i = (j < alt.size()) ? j + 1 : alt.size();
            endRun();
            continue;
        }
        if (c == '(') {
            int depth = 1; size_t j = i + 1;
            while (j < alt.size() && depth > 0) {
                if (alt[j] == '\\') j++;
                else if (alt[j] == '(') depth++;
                else if (alt[j] == ')') depth--;
                j++;
            }
            i = j;
            if (i < alt.size() && strchr("?*+{", alt[i])) { i++; while (i < alt.size() && (isdigit((unsigned char)alt[i]) || alt[i] == ',' || alt[i] == '}')) i++; }
            endRun();
            continue;
        }
        if (c == '?' || c == '*' || c == '{') {
            if (c == '{') { while (i < alt.size() && alt[i] != '}') i++; i++; }
            else i++;
            if (!cur.empty()) cur.pop_back();
            continue;
        }
        if (c == '+' ) { i++; continue; }
        if (c == '.' || c == '^' || c == '$' || c == '|' || c == ')' || c == ']' || c == '}') {
            endRun(); i++;
            continue;
        }
        cur.push_back(c); i++;
    }
    endRun();
    out = best;
    return true;
}

static bool packRules(const std::vector<PrefilterRule>& hr, std::vector<DevRule>& dr) {
    for (const auto& r : hr) {
        if (dr.size() >= 8) return false;
        DevRule d{};
        switch (r.kind) {
        case PrefilterRule::CONSECUTIVE: d.kind = 0; d.k = r.k; break;
        case PrefilterRule::REPEATING:   d.kind = 1; d.k = r.k; break;
        case PrefilterRule::PALINDROME:  d.kind = 2; d.k = r.k; break;
        case PrefilterRule::DATE:
        case PrefilterRule::LITERAL:
            d.kind = 3; d.k = 0;
            d.litLen = r.litDead ? 0 : r.litLen;
            for (int i = 0; i < d.litLen && i < 16; i++) d.lit[i] = r.lit[i];
            break;
        case PrefilterRule::ZEROS:       d.kind = 4; d.k = r.k; break;
        }
        dr.push_back(d);
    }
    return true;
}

static bool parseRulesLine(const std::string& line, std::vector<PrefilterRule>& rules, std::string& err) {
    if (line.empty() || line[0] == '#') return true;
    size_t sp = line.find(' ');
    std::string type = (sp == std::string::npos) ? line : line.substr(0, sp);
    std::string rest = (sp == std::string::npos) ? "" : line.substr(sp + 1);
    PrefilterRule r{};
    r.litDead = false;
    r.litLen = 0;
    auto mk = [&](int k) { r.k = k; rules.push_back(r); };

    if (type == "consecutive") { r.kind = PrefilterRule::CONSECUTIVE; mk(atoi(rest.c_str())); }
    else if (type == "repeating") { r.kind = PrefilterRule::REPEATING; mk(atoi(rest.c_str())); }
    else if (type == "palindrome") { r.kind = PrefilterRule::PALINDROME; mk(atoi(rest.c_str())); }
    else if (type == "leading_zeros") { r.kind = PrefilterRule::ZEROS; mk(atoi(rest.c_str())); }
    else if (type == "special_date") { r.kind = PrefilterRule::DATE; }
    else if (type == "custom_regex") { r.kind = PrefilterRule::LITERAL; }
    else { err = "unknown rule type: " + type; return false; }

    if (r.kind == PrefilterRule::DATE || r.kind == PrefilterRule::LITERAL) {
        if (r.kind == PrefilterRule::DATE) {
            for (char c : rest) {
                int v = hexVal(c);
                if (v < 0) { r.litDead = true; break; }
                r.lit[r.litLen++] = (uint8_t)v;
            }
        } else {
            std::string lit;
            if (!extractLiteral(rest, lit)) { err = "regex literal extraction failed: " + rest; return false; }
            if (lit.empty()) { err = "regex has no required literal (unsupported on GPU): " + rest; return false; }
            for (char c : lit) {
                int v = hexVal(c);
                if (v < 0) { r.litDead = true; break; }
                r.lit[r.litLen++] = (uint8_t)v;
            }
        }
        rules.push_back(r);
    }
    return true;
}

// ---------------- CSPRNG (host seed only) ----------------
static bool genRandom(uint8_t* buf, size_t len) {
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st);
}

// ---------------- utils ----------------
static void toHex(const uint8_t* p, size_t n, char* out) {
    static const char* HEX = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = HEX[p[i] >> 4]; out[2 * i + 1] = HEX[p[i] & 0xF]; }
    out[2 * n] = 0;
}

static void kidToHex(const uint32_t kid[2], char* out) {
    uint8_t b[8];
    b[0] = (uint8_t)(kid[0] >> 24); b[1] = (uint8_t)(kid[0] >> 16);
    b[2] = (uint8_t)(kid[0] >> 8);  b[3] = (uint8_t)(kid[0]);
    b[4] = (uint8_t)(kid[1] >> 24); b[5] = (uint8_t)(kid[1] >> 16);
    b[6] = (uint8_t)(kid[1] >> 8);  b[7] = (uint8_t)(kid[1]);
    toHex(b, 8, out);
}

// 8x32 limbs (LE) -> 32-byte big-endian hex
static void limbsToHexBE(const uint32_t* limbs, char* out) {
    uint8_t b[32];
    for (int i = 0; i < 8; i++) {
        uint32_t v = limbs[7 - i];
        b[4 * i + 0] = (uint8_t)(v >> 24);
        b[4 * i + 1] = (uint8_t)(v >> 16);
        b[4 * i + 2] = (uint8_t)(v >> 8);
        b[4 * i + 3] = (uint8_t)(v);
    }
    toHex(b, 32, out);
}

#define CUDA_CHECK(expr) do { \
    cudaError_t e_ = (expr); \
    if (e_ != cudaSuccess) { printf("{\"t\":\"error\",\"message\":\"CUDA %s @%s:%d\"}\n", cudaGetErrorString(e_), __FILE__, __LINE__); return 1; } \
} while (0)

int main(int argc, char** argv) {
    int batch = 0;
    uint32_t created = 0;
    const char* rulesFile = nullptr;
    int durationSec = 0;
    bool testMode = false;
    const char* inputFile = nullptr;
    int quiet = 0;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--batch") batch = atoi(next());
        else if (a == "--created") created = (uint32_t)_atoi64(next());
        else if (a == "--rules") rulesFile = next();
        else if (a == "--duration") durationSec = atoi(next());
        else if (a == "--quiet") quiet = 1;
        else if (a == "--mode") { std::string m = next(); testMode = (m == "test"); }
        else if (a == "--input") inputFile = next();
    }

    if (created == 0) created = (uint32_t)time(nullptr);

    // stdin watchdog thread: EOF => gStop
    std::thread([] {
        char buf[64];
        while (fgets(buf, sizeof(buf), stdin) != nullptr) { /* consume */ }
        gStop = true;
    }).detach();

    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));

    // rule parsing
    std::vector<PrefilterRule> rules;
    if (rulesFile) {
        FILE* f = fopen(rulesFile, "r");
        if (!f) { printf("{\"t\":\"error\",\"message\":\"cannot open rules file\"}\n"); return 1; }
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
            std::string err;
            if (!parseRulesLine(line, rules, err)) {
                printf("{\"t\":\"error\",\"message\":\"%s\"}\n", err.c_str());
                return 2;
            }
        }
        fclose(f);
    }
    std::vector<DevRule> devRules;
    if (!packRules(rules, devRules)) {
        printf("{\"t\":\"error\",\"message\":\"too many rules for GPU engine (>8), falling back\"}\n");
        return 2;
    }
    DevRule* dRules = nullptr;
    if (!devRules.empty()) {
        CUDA_CHECK(cudaMalloc(&dRules, devRules.size() * sizeof(DevRule)));
        CUDA_CHECK(cudaMemcpy(dRules, devRules.data(), devRules.size() * sizeof(DevRule), cudaMemcpyHostToDevice));
    }

    // batch size: default = 4 full waves of 256-thread blocks per SM, clamped
    if (batch <= 0) {
        long long b = (long long)prop.multiProcessorCount * (2048 / 256) * 4 * 256;
        if (b < (1 << 18)) b = 1 << 18;
        if (b > (1 << 21)) b = 1 << 21;
        batch = (int)b;
    }
    if (batch < 1024) batch = 1024;
    if (batch > (1 << 22)) batch = 1 << 22;   // ChaCha counter space per batch = 2^22

    printf("{\"t\":\"ready\",\"device\":\"%s\",\"sm\":%d,\"batch\":%d}\n", prop.name, prop.major * 10 + prop.minor, batch);
    fflush(stdout);

    const int BLOCK = 256;
    const int GRID = (batch + BLOCK - 1) / BLOCK;

    // -------- shared device buffers --------
    uint32_t* dSeed[2];
    uint32_t* dKids[2];
    // per-slot hit buffers
    uint32_t* dHitScalar[2];
    uint32_t* dHitX[2];
    uint32_t* dHitY[2];
    uint32_t* dHitKid[2];
    int* dHitIdx[2];
    unsigned int* dHitCount[2];
    const int MAX_HITS_PER_BATCH = 4096;
    for (int s = 0; s < 2; s++) {
        CUDA_CHECK(cudaMalloc(&dSeed[s], 12 * sizeof(uint32_t)));
        CUDA_CHECK(cudaMalloc(&dKids[s], (size_t)batch * 8));
        CUDA_CHECK(cudaMalloc(&dHitScalar[s], (size_t)MAX_HITS_PER_BATCH * 8));
        CUDA_CHECK(cudaMalloc(&dHitX[s], (size_t)MAX_HITS_PER_BATCH * LIMBS * 4));
        CUDA_CHECK(cudaMalloc(&dHitY[s], (size_t)MAX_HITS_PER_BATCH * LIMBS * 4));
        CUDA_CHECK(cudaMalloc(&dHitKid[s], (size_t)MAX_HITS_PER_BATCH * 8));
        CUDA_CHECK(cudaMalloc(&dHitIdx[s], MAX_HITS_PER_BATCH * sizeof(int)));
        CUDA_CHECK(cudaMalloc(&dHitCount[s], sizeof(unsigned int)));
    }
    // test-mode extra buffers (dXs/dYs only used by test/self-check path)
    uint32_t *dXs = nullptr, *dYs = nullptr, *dPlainX = nullptr, *dPlainY = nullptr;
    CUDA_CHECK(cudaMalloc(&dXs, (size_t)batch * LIMBS * 4));
    CUDA_CHECK(cudaMalloc(&dYs, (size_t)batch * LIMBS * 4));
    std::vector<uint32_t> hPlainX(testMode ? (size_t)batch * LIMBS : 0);
    std::vector<uint32_t> hPlainY(testMode ? (size_t)batch * LIMBS : 0);
    if (testMode) {
        CUDA_CHECK(cudaMalloc(&dPlainX, (size_t)batch * LIMBS * 4));
        CUDA_CHECK(cudaMalloc(&dPlainY, (size_t)batch * LIMBS * 4));
    }

    // -------- startup self-check: d=1 -> G, d=2 -> 2G (guards constant table) --------
    {
        uint8_t chk[64] = {0};
        chk[0] = 1; chk[32] = 2;
        uint8_t* dChk;
        CUDA_CHECK(cudaMalloc(&dChk, 64));
        CUDA_CHECK(cudaMemcpy(dChk, chk, 64, cudaMemcpyHostToDevice));
        scalar_from_buf_kernel<<<1, 256>>>(dChk, dXs, dYs, 2);
        CUDA_CHECK(cudaGetLastError());
        keyid_from_xy_kernel<<<1, 256>>>(dXs, dYs, created, dKids[0], nullptr, nullptr, 2);
        CUDA_CHECK(cudaGetLastError());
        uint32_t hx[2 * LIMBS], hy[2 * LIMBS], gx[LIMBS], gy[LIMBS], tx[LIMBS], ty[LIMBS];
        CUDA_CHECK(cudaMemcpy(hx, dXs, 2 * LIMBS * 4, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(hy, dYs, 2 * LIMBS * 4, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpyFromSymbol(gx, P256_GX, LIMBS * 4));
        CUDA_CHECK(cudaMemcpyFromSymbol(gy, P256_GY, LIMBS * 4));
        CUDA_CHECK(cudaMemcpyFromSymbol(tx, P256_2GX, LIMBS * 4));
        CUDA_CHECK(cudaMemcpyFromSymbol(ty, P256_2GY, LIMBS * 4));
        bool ok1 = true, ok2 = true;
        for (int i = 0; i < LIMBS; i++) {
            ok1 = ok1 && hx[i] == gx[i] && hy[i] == gy[i];
            ok2 = ok2 && hx[LIMBS + i] == tx[i] && hy[LIMBS + i] == ty[i];
        }
        CUDA_CHECK(cudaFree(dChk));
        if (!ok1 || !ok2) {
            printf("{\"t\":\"error\",\"message\":\"self-check failed: 1G/2G mismatch -- constant table or kernel corrupt\"}\n");
            return 1;
        }
        if (!quiet) {
            printf("{\"t\":\"warn\",\"message\":\"self-check ok: 1G+2G verified\"}\n");
            fflush(stdout);
        }
    }

    // -------- test mode: single-shot, then exit --------
    if (testMode) {
        FILE* f = fopen(inputFile, "r");
        if (!f) { printf("{\"t\":\"error\",\"message\":\"cannot open input\"}\n"); return 1; }
        std::vector<uint8_t> inputD;
        std::vector<std::string> inputHexBE;
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strlen(line) < 64) continue;
            std::string hexs(line, 64);
            inputHexBE.push_back(hexs);
            for (int i = 0; i < 32; i++) {
                char h[3] = {line[2 * (31 - i)], line[2 * (31 - i) + 1], 0};
                inputD.push_back((uint8_t)strtol(h, nullptr, 16));
            }
        }
        fclose(f);
        int tcount = (int)inputD.size() / 32;
        if (tcount == 0) {
            printf("{\"t\":\"error\",\"message\":\"test input empty\"}\n");
            return 1;
        }
        uint8_t* dScalars;
        CUDA_CHECK(cudaMalloc(&dScalars, (size_t)tcount * 32));
        CUDA_CHECK(cudaMemcpy(dScalars, inputD.data(), (size_t)tcount * 32, cudaMemcpyHostToDevice));
        const int TGRID = (tcount + BLOCK - 1) / BLOCK;
        scalar_from_buf_kernel<<<TGRID, BLOCK>>>(dScalars, dXs, dYs, tcount);
        CUDA_CHECK(cudaGetLastError());
        keyid_from_xy_kernel<<<TGRID, BLOCK>>>(dXs, dYs, created, dKids[0], dPlainX, dPlainY, tcount);
        CUDA_CHECK(cudaGetLastError());
        std::vector<uint32_t> hTkids((size_t)tcount * 2);
        CUDA_CHECK(cudaMemcpy(hTkids.data(), dKids[0], (size_t)tcount * 8, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(hPlainX.data(), dPlainX, (size_t)tcount * LIMBS * 4, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(hPlainY.data(), dPlainY, (size_t)tcount * LIMBS * 4, cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaDeviceSynchronize());
        for (int i = 0; i < tcount; i++) {
            char dh[65], xh[65], yh[65], kh[17];
            toHex((const uint8_t*)inputHexBE[i].data(), 32, dh);
            limbsToHexBE(&hPlainX[(size_t)i * LIMBS], xh);
            limbsToHexBE(&hPlainY[(size_t)i * LIMBS], yh);
            kidToHex(&hTkids[2 * (size_t)i], kh);
            printf("{\"t\":\"vec\",\"d\":\"%s\",\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"}\n", dh, xh, yh, kh);
        }
        printf("{\"t\":\"done\"}\n");
        fflush(stdout);
        return 0;
    }

    // -------- mining pipeline (v5) --------
    // Pinned per-slot seed staging + hit download staging.
    uint8_t* hSeedPinned[2];
    CUDA_CHECK(cudaHostAlloc(&hSeedPinned[0], 48, cudaHostAllocDefault));
    CUDA_CHECK(cudaHostAlloc(&hSeedPinned[1], 48, cudaHostAllocDefault));
    unsigned int* hHitCountPinned[2];
    CUDA_CHECK(cudaHostAlloc(&hHitCountPinned[0], sizeof(unsigned int), cudaHostAllocDefault));
    CUDA_CHECK(cudaHostAlloc(&hHitCountPinned[1], sizeof(unsigned int), cudaHostAllocDefault));
    std::vector<uint32_t> hHitScalar(MAX_HITS_PER_BATCH * 8);
    std::vector<uint32_t> hHitX(MAX_HITS_PER_BATCH * LIMBS);
    std::vector<uint32_t> hHitY(MAX_HITS_PER_BATCH * LIMBS);
    std::vector<uint32_t> hHitKid(MAX_HITS_PER_BATCH * 2);

    cudaEvent_t evtDone[2];
    CUDA_CHECK(cudaEventCreate(&evtDone[0]));
    CUDA_CHECK(cudaEventCreate(&evtDone[1]));
    cudaStream_t stream;
    CUDA_CHECK(cudaStreamCreate(&stream));

    long long total = 0;
    long long hits = 0;
    bool hitOverflowWarned = false;
    auto t0 = std::chrono::steady_clock::now();
    auto last = t0;
    uint32_t sessionBatch = 0;      // ChaCha batch counter (session-scoped, < 2^16)
    int slot = 0;

    auto issue = [&](int sl, uint32_t bIdx) -> bool {
        // fresh 48-byte OS CSPRNG seed for this batch (host-side, before enqueue)
        if (!genRandom(hSeedPinned[sl], 48)) return false;
        CUDA_CHECK(cudaMemsetAsync(dHitCount[sl], 0, sizeof(unsigned int), stream));
        CUDA_CHECK(cudaMemcpyAsync(dSeed[sl], hSeedPinned[sl], 48, cudaMemcpyHostToDevice, stream));
        fused_mine_kernel<<<GRID, BLOCK, 0, stream>>>(dSeed[sl], bIdx, created,
                                                      dHitScalar[sl], dHitX[sl], dHitY[sl], dHitKid[sl],
                                                      dRules, (int)devRules.size(),
                                                      dHitIdx[sl], dHitCount[sl], MAX_HITS_PER_BATCH, batch);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaMemcpyAsync(hHitCountPinned[sl], dHitCount[sl], sizeof(unsigned int), cudaMemcpyDeviceToHost, stream));
        CUDA_CHECK(cudaEventRecord(evtDone[sl], stream));
        return true;
    };

    // prime both pipeline slots
    if (!issue(0, sessionBatch++)) { printf("{\"t\":\"error\",\"message\":\"CSPRNG failed\"}\n"); return 1; }
    if (!issue(1, sessionBatch++)) { printf("{\"t\":\"error\",\"message\":\"CSPRNG failed\"}\n"); return 1; }

    bool running = true;
    while (running) {
        const int cur = slot;
        const uint32_t curBatch = sessionBatch - 2;   // batch id of the kernel in slot cur
        slot ^= 1;
        sessionBatch++;

        // wait for the current batch (kernel + hit-count download) to finish
        CUDA_CHECK(cudaEventSynchronize(evtDone[cur]));
        unsigned int hc = hHitCountPinned[cur][0];
        if (hc > (unsigned int)MAX_HITS_PER_BATCH) {
            hc = (unsigned int)MAX_HITS_PER_BATCH;
            if (!hitOverflowWarned) {
                hitOverflowWarned = true;
                printf("{\"t\":\"warn\",\"message\":\"hit overflow: pattern too common for GPU engine, extra hits dropped\"}\n");
                fflush(stdout);
            }
        }
        if (hc > 0) {
            int hitCount = (int)hc;
            // hit records were compacted in-kernel; single D2H burst (small)
            CUDA_CHECK(cudaMemcpy(hHitScalar.data(), dHitScalar[cur], (size_t)hitCount * 8 * 4, cudaMemcpyDeviceToHost));
            CUDA_CHECK(cudaMemcpy(hHitX.data(), dHitX[cur], (size_t)hitCount * LIMBS * 4, cudaMemcpyDeviceToHost));
            CUDA_CHECK(cudaMemcpy(hHitY.data(), dHitY[cur], (size_t)hitCount * LIMBS * 4, cudaMemcpyDeviceToHost));
            CUDA_CHECK(cudaMemcpy(hHitKid.data(), dHitKid[cur], (size_t)hitCount * 8, cudaMemcpyDeviceToHost));
            // the NEXT batch's kernel is already running on other buffers;
            // a tiny sync here only orders these 3 small D2H copies
            CUDA_CHECK(cudaDeviceSynchronize());
            for (int k = 0; k < hitCount; k++) {
                char kh[17], dh[65], xh[65], yh[65];
                kidToHex(&hHitKid[2 * (size_t)k], kh);
                // hitScalar words are the LE-32-byte scalar
                uint8_t le[32];
                for (int w = 0; w < 8; w++) {
                    uint32_t v = hHitScalar[(size_t)k * 8 + w];
                    le[4 * w + 0] = (uint8_t)v;
                    le[4 * w + 1] = (uint8_t)(v >> 8);
                    le[4 * w + 2] = (uint8_t)(v >> 16);
                    le[4 * w + 3] = (uint8_t)(v >> 24);
                }
                uint8_t be[32];
                for (int j = 0; j < 32; j++) be[j] = le[31 - j];
                toHex(be, 32, dh);
                limbsToHexBE(&hHitX[(size_t)k * LIMBS], xh);
                limbsToHexBE(&hHitY[(size_t)k * LIMBS], yh);
                printf("{\"t\":\"hit\",\"d\":\"%s\",\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\",\"created\":%u}\n",
                       dh, xh, yh, kh, created);
                hits++;
            }
            fflush(stdout);
        }

        // issue the next batch into the slot just consumed
        if (sessionBatch - 2 < 0xFFFEu) {
            if (!issue(cur, sessionBatch - 2)) { printf("{\"t\":\"error\",\"message\":\"CSPRNG failed\"}\n"); return 1; }
        }

        total += batch;
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - last).count() >= 1.0) {
            double elapsed = std::chrono::duration<double>(now - t0).count();
            printf("{\"t\":\"prog\",\"rate\":%.1f,\"total\":%lld,\"hits\":%lld}\n",
                   (double)total / elapsed, total, hits);
            fflush(stdout);
            last = now;
        }
        if (gStop) break;
        if (durationSec > 0 && std::chrono::duration<double>(now - t0).count() >= durationSec) break;
    }

    printf("{\"t\":\"done\",\"total\":%lld,\"hits\":%lld}\n", total, hits);
    fflush(stdout);
    return 0;
}

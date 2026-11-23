// 原生快速密钥生成 + OpenPGP 密钥组装（纯 JS，worker 与后端共用）
//
// ===== 为什么要自己造 =====
// 实测（单线程）：
//   openpgp.generateKey (ecc/curve25519)     ~ 70-90  keys/s
//   openpgp.generateKey (ecc/nistP256)      ~ 85    keys/s
//   native crypto.generateKeyPairSync P-256 ~ 6000  keys/s
// 根因：openpgp 的曲线运算走 noble-curves 的 BigInt JS 实现，
//       而 Node 原生 crypto 走 OpenSSL，差 50-70 倍。
//
// ===== 已逆向确认并实测验证的 OpenPGP 格式 =====
//
// 公钥包体 (writePublicKey, 82B)：
//   version(1)=4 | created(4) | algo(1)=0x13(ECDSA) | oidLen(1)=8
//   | oid(8)=2a8648ce3d030107 | mpi(Q)
//   其中 Q = 0x04 || X(32) || Y(32)（未压缩点），mpi 位长度 = 有效位数
//
// 秘密密钥包体 (SecretKeyPacket, tag 5)：
//   [公钥部分：version|created|algo|oidLen|oid|mpi(Q)]
//   | s2kUsage(1)=0（明文）
//   | mpi(d)（32 字节私钥标量）
//   | checksum(2)（所有字节之和 % 65535，只覆盖 secret 部分）
//
// 指纹算法（openpgp 源码 writeForHash，已交叉验证）：
//   fingerprint = SHA1( 0x99 || uint16be(len) || writePublicKey() )
//   keyId       = fingerprint 的后 16 位 hex
//
// ===== 工作流程 =====
//   搜索阶段：原生 crypto 生成 (d, Q) -> 组装公钥包体 -> 算长 Key ID -> 判定命中
//             速度约为 openpgp 的 60-70 倍
//   命中阶段：用 openpgp 的 readPrivateKey + reformatKey 把同一套材料
//             补齐成完整可用的 OpenPGP 密钥（UID、自签名、Armor）
//             keyID 与搜索阶段完全一致

import crypto from 'node:crypto';

// ECDSA/ECDH P-256 的 OID: 1.2.840.10045.3.1.7
const OID_NIST_P256 = Buffer.from('2a8648ce3d030107', 'hex');
const ALGO_ECDSA = 19;

/**
 * MPI 编码：2 字节有效位长度 + 最少字节数的载荷（RFC 4880 §3.2）
 *
 * 位长必须「从最高非零位算起」，并且载荷必须与位长自洽：
 * 若剥掉了前导零位，就不能保留前导零字节，否则读取方按 ceil(bits/8)
 * 取字节会少读，导致后续字段错位（openpgp 会报 "Error reading MPIs"）。
 */
function mpi(data) {
  // 去掉前导零字节（至少保留 1 字节）
  let start = 0;
  while (start < data.length - 1 && data[start] === 0) start++;
  const payload = data.subarray(start);

  // 从最高非零位算有效位数
  let bits;
  const first = payload[0];
  if (first === 0) {
    bits = 8; // 值本身为零时的兜底；合法的 EC 标量不会走到这里
  } else {
    let lead = 0;
    while (lead < 8 && (first & (0x80 >> lead)) === 0) lead++;
    bits = (payload.length - 1) * 8 + (8 - lead);
  }

  return Buffer.concat([Buffer.from([(bits >> 8) & 0xff, bits & 0xff]), payload]);
}

/** OpenPGP v4 checksum：所有字节之和 % 65535 */
function writeChecksum(buf) {
  let s = 0;
  for (const b of buf) s = (s + b) & 0xffff;
  return Buffer.from([(s >> 8) & 0xff, s & 0xff]);
}

/** 组装公钥包体（writePublicKey）—— 供 GPU worker 复用,故导出 */
function buildPublicKeyBody(created, q) {
  return Buffer.concat([
    Buffer.from([4]),                       // version 4
    created,                                // creation time
    Buffer.from([ALGO_ECDSA]),              // public-key algorithm (ECDSA)
    Buffer.from([OID_NIST_P256.length]),
    OID_NIST_P256,
    mpi(q),                                 // 公钥点 MPI
  ]);
}

/** 组装秘密密钥包体（SecretKeyPacket, tag 5） */
function buildSecretKeyBody(created, q, d) {
  const publicPart = buildPublicKeyBody(created, q);
  // d 用规范 MPI 编码：位长与载荷自洽（首字节为 0x00 时自动去掉前导零字节）
  const secretPart = mpi(d);
  const checksum = writeChecksum(secretPart);
  return Buffer.concat([publicPart, Buffer.from([0]), secretPart, checksum]);
}

/** 包头（tag + 长度） */
export function packet(tag, payload) {
  const len = payload.length;
  const header = len < 192
    ? Buffer.from([0xC0 | tag, len])
    : Buffer.from([0xC0 | tag, 192 + (len >> 8), len & 0xff]);
  return Buffer.concat([header, payload]);
}

// 以下三个内部函数导出给 GPU worker(gpu.worker.mjs)复用,
// 保证 GPU 命中重建的密钥字节级一致
export { mpi, buildPublicKeyBody, buildSecretKeyBody };

/** 指纹 = SHA1(0x99 || uint16be(len) || body) */
export function computeFingerprint(body) {
  const prefix = Buffer.from([0x99, (body.length >> 8) & 0xff, body.length & 0xff]);
  return crypto.createHash('sha1').update(Buffer.concat([prefix, body])).digest('hex');
}

/** 长 Key ID = 指纹后 16 位 */
export function extractKeyId(fingerprint) {
  return String(fingerprint).toLowerCase().replace(/\s+/g, '').slice(-16);
}

/**
 * 用 Node 原生 crypto 生成 P-256 密钥材料并计算长 Key ID。
 * 比 openpgp 快约 60-70 倍。
 * @returns {{ fingerprint, keyId, secretKeyBinary, publicKeyBody }}
 */
export function generateFastKeyMaterial() {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

  const pubJwk = kp.publicKey.export({ format: 'jwk' });
  const privJwk = kp.privateKey.export({ format: 'jwk' });
  const X = Buffer.from(pubJwk.x, 'base64url');
  const Y = Buffer.from(pubJwk.y, 'base64url');
  const d = Buffer.from(privJwk.d, 'base64url');
  const q = Buffer.concat([Buffer.from([0x04]), X, Y]);

  const now = Math.floor(Date.now() / 1000);
  const created = Buffer.alloc(4);
  created.writeUInt32BE(now, 0);

  const publicKeyBody = buildPublicKeyBody(created, q);
  const fingerprint = computeFingerprint(publicKeyBody);

  return {
    fingerprint,
    keyId: extractKeyId(fingerprint),
    // 完整的秘密密钥包（可直接喂给 openpgp.readPrivateKey）
    secretKeyBinary: packet(5, buildSecretKeyBody(created, q, d)),
    publicKeyBody,
  };
}

// ========== 规则匹配（只针对 16 位长 Key ID） ==========

function matchConsecutive(text, minLength) {
  const m = new RegExp(`(\\w)\\1{${minLength - 1},}`, 'g').exec(text);
  return m ? { matched: true, position: m.index, matchedText: m[0] } : { matched: false, position: -1, matchedText: '' };
}

function matchRepeating(text, minLength) {
  const m = new RegExp(`(\\w{${minLength}})\\1+`, 'g').exec(text);
  return m ? { matched: true, position: m.index, matchedText: m[0] } : { matched: false, position: -1, matchedText: '' };
}

function matchPalindrome(text, minLength) {
  for (let i = 0; i <= text.length - minLength; i++) {
    const sub = text.substring(i, i + minLength);
    const lower = sub.toLowerCase();
    if (lower === lower.split('').reverse().join('')) {
      return { matched: true, position: i, matchedText: sub };
    }
  }
  return { matched: false, position: -1, matchedText: '' };
}

function matchSpecialDate(text, pattern) {
  if (!pattern) return { matched: false, position: -1, matchedText: '' };
  const idx = text.indexOf(pattern);
  return idx !== -1
    ? { matched: true, position: idx, matchedText: pattern }
    : { matched: false, position: -1, matchedText: '' };
}

function matchCustomRegex(text, regex) {
  if (!regex) return { matched: false, position: -1, matchedText: '' };
  try {
    const m = new RegExp(regex, 'g').exec(text);
    return m ? { matched: true, position: m.index, matchedText: m[0] } : { matched: false, position: -1, matchedText: '' };
  } catch {
    return { matched: false, position: -1, matchedText: '' };
  }
}

function matchLeadingZeros(text, zeroCount) {
  const zeros = '0'.repeat(zeroCount);
  const idx = text.indexOf(zeros);
  return idx !== -1
    ? { matched: true, position: idx, matchedText: zeros }
    : { matched: false, position: -1, matchedText: '' };
}

function matchSingle(rule, text) {
  const p = rule.params || {};
  switch (rule.type) {
    case 'consecutive': return matchConsecutive(text, p.minLength || 5);
    case 'repeating': return matchRepeating(text, p.minLength || 3);
    case 'palindrome': return matchPalindrome(text, p.minLength || 5);
    case 'special_date': return matchSpecialDate(text, p.pattern || '');
    case 'custom_regex': return matchCustomRegex(text, p.pattern || '');
    case 'leading_zeros': return matchLeadingZeros(text, p.zeroCount || 5);
    default: return { matched: false, position: -1, matchedText: '' };
  }
}

/**
 * 对 16 位长 Key ID 应用规则（独立规则 + 规则组）
 * @returns {{ matched: boolean, hits: Array }}
 */
export function matchRules(keyId, independentRules, groups = [], logicOperator = 'OR') {
  const hits = [];

  // 独立规则
  const enabled = (independentRules || []).filter(r => r.enabled);
  for (const rule of enabled) {
    const res = matchSingle(rule, keyId);
    if (res.matched) {
      hits.push({
        ruleId: rule.id,
        ruleName: rule.name,
        patternType: rule.type,
        color: rule.color,
        priority: rule.priority ?? 50,
        position: res.position,
        matchedText: res.matchedText,
      });
    }
  }

  const independentMatched = logicOperator === 'AND'
    ? (hits.length === enabled.length && enabled.length > 0)
    : hits.length > 0;

  // 规则组（每个组用自己的规则集合）
  for (const group of groups || []) {
    if (!group.enabled) continue;
    const rules = (group.rules || []).filter(r => r.enabled);
    if (rules.length === 0) continue;

    const groupHits = [];
    let allHit = true;
    for (const rule of rules) {
      const res = matchSingle(rule, keyId);
      if (res.matched) {
        groupHits.push({
          ruleId: rule.id,
          ruleName: rule.name,
          patternType: rule.type,
          color: rule.color,
          priority: group.priority,
          position: res.position,
          matchedText: res.matchedText,
          groupId: group.id,
          groupName: group.name,
        });
      } else {
        allHit = false;
      }
    }

    const groupMatched = group.logicOperator === 'AND'
      ? (allHit && groupHits.length === rules.length)
      : groupHits.length > 0;

    if (groupMatched) hits.push(...groupHits);
  }

  return { matched: independentMatched || hits.length > 0, hits };
}

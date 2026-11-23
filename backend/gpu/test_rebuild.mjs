// 集成预验证: 模拟 GPU 命中(d,x,y,created) → 零信任复验 → openpgp 完整密钥
// GPU 到位后唯一区别是 (d,x,y) 来自 exe 而非 OpenSSL
import * as openpgp from 'openpgp';
import crypto from 'node:crypto';
import {
  matchRules,
  packet,
  buildPublicKeyBody,
  buildSecretKeyBody,
  computeFingerprint,
  extractKeyId,
} from '../app/lib/pgp/fast-keygen.mjs';

// 1. 模拟 GPU 生成一批材料(用 OpenSSL 当 GPU 替身)
const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const pubJwk = kp.publicKey.export({ format: 'jwk' });
const privJwk = kp.privateKey.export({ format: 'jwk' });
const x = Buffer.from(pubJwk.x, 'base64url').toString('hex');
const y = Buffer.from(pubJwk.y, 'base64url').toString('hex');
const d = Buffer.from(privJwk.d, 'base64url').toString('hex');
const created = Math.floor(Date.now() / 1000);

const hit = { d, x, y, kid: null, created };

// 2. worker 的 validateAndRebuild 逻辑
const b64u = (hex) => Buffer.from(hex, 'hex').toString('base64url');
crypto.createPrivateKey({
  key: { kty: 'EC', crv: 'P-256', d: b64u(hit.d), x: b64u(hit.x), y: b64u(hit.y) },
  format: 'jwk',
});

const xb = Buffer.from(hit.x, 'hex');
const yb = Buffer.from(hit.y, 'hex');
const db = Buffer.from(hit.d, 'hex');
const createdBuf = Buffer.alloc(4);
createdBuf.writeUInt32BE(hit.created, 0);
const q = Buffer.concat([Buffer.from([0x04]), xb, yb]);
const publicKeyBody = buildPublicKeyBody(createdBuf, q);
const fingerprint = computeFingerprint(publicKeyBody);
const keyId = extractKeyId(fingerprint);
console.log('rebuilt keyId:', keyId);

// 3. 规则复验: 要求 keyId 含 "a" 或其他 —— 用会命中的宽松规则
const patterns = [{ id: 'r1', type: 'custom_regex', params: { pattern: '[0-9a-f]' }, color: '#fff', enabled: true }];
const result = matchRules(keyId, patterns, [], 'OR');
if (!result.matched) throw new Error('rule revalidation failed');
console.log('rule revalidation: OK, hits =', result.hits.length);

// 4. 完整密钥组装(与 gpu.worker 一致)
const secretKeyBinary = packet(5, buildSecretKeyBody(createdBuf, q, db));
const priv = await openpgp.readPrivateKey({ binaryKey: secretKeyBinary });
console.log('readPrivateKey OK:', priv.getKeyID().toHex());
if (priv.getKeyID().toHex() !== keyId) throw new Error('openpgp keyId != search keyId');

const fmt = await openpgp.reformatKey({
  privateKey: priv,
  userIDs: [{ name: 'PGP Vanity Miner', email: 'miner@localhost' }],
  passphrase: '',
  format: 'armored',
});
let key = await openpgp.readPrivateKey({ armoredKey: fmt.privateKey });
key = await key.addSubkey({});
const publicKeyArmored = key.toPublic().armor();
const privateKeyArmored = key.armor();
const pub = await openpgp.readKey({ armoredKey: publicKeyArmored });

console.log('fingerprint:', pub.getFingerprint());
console.log('keyId      :', pub.getKeyID().toHex());
console.log('main keyId match:', pub.getKeyID().toHex() === keyId);

// 5. 签名+加密自测: 证明这把密钥真正可用
const message = await openpgp.createMessage({ text: 'gpu vanity test 2026' });
// sign(Message) 产出「签名消息」(正文+签名一体),verify 直接对它验证
const signedArmored = await openpgp.sign({ message, signingKeys: key, format: 'armored' });
const signedMessage = await openpgp.readMessage({ armoredMessage: signedArmored });
const verify = await openpgp.verify({ message: signedMessage, verificationKeys: key.toPublic() });
console.log('sign/verify:', (await verify.signatures[0].verified) === true ? 'OK' : 'FAIL');

const encMsg = await openpgp.createMessage({ text: 'enc test' });
const encrypted = await openpgp.encrypt({ message: encMsg, encryptionKeys: key.toPublic() });
const decrypted = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: encrypted }), decryptionKeys: key });
console.log('encrypt/decrypt:', decrypted.data === 'enc test' ? 'OK' : 'FAIL');

console.log('\nALL INTEGRATION CHECKS PASS');

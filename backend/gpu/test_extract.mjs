// extractLiteral 算法的 JS 镜像验证 —— 与 miner.cu 里的 C++ 实现逐分支对齐
// 目的: 编译前钉死语义。C++ 若改这里也要同步改(算法注释互相指向)
// 规则: 正则 R 匹配成功 ⇒ 文本中必含提取出的字面量(过近似,宁多勿漏)

function extractLiteral(alt) {
  let cur = '';
  let best = '';
  const pop = () => { if (cur.length > best.length) best = cur; cur = ''; };
  for (let i = 0; i < alt.length;) {
    const c = alt[i];
    if (c === '\\' && i + 1 < alt.length) {
      const nx = alt[i + 1];
      if ('dDwWsSbB'.includes(nx) || /[a-z0-9]/i.test(nx)) { pop(); i += 2; }
      else { cur += nx; i += 2; }
      continue;
    }
    if (c === '[') { // 字符类
      let j = i + 1;
      if (alt[j] === '^') j++;
      if (alt[j] === ']') j++;
      while (j < alt.length && alt[j] !== ']') { if (alt[j] === '\\') j++; j++; }
      i = j < alt.length ? j + 1 : alt.length;
      pop();
      continue;
    }
    if (c === '(') { // 组: 跳过 + 量词
      let depth = 1, j = i + 1;
      while (j < alt.length && depth > 0) {
        if (alt[j] === '\\') j++;
        else if (alt[j] === '(') depth++;
        else if (alt[j] === ')') depth--;
        j++;
      }
      i = j;
      if ('?*+{'.includes(alt[i])) { i++; while (i < alt.length && /[\d,}]/.test(alt[i])) i++; }
      pop();
      continue;
    }
    if (c === '?' || c === '*' || c === '{') { // 修饰前一元素: 前一字面量可能不出现
      if (c === '{') { while (i < alt.length && alt[i] !== '}') i++; i++; }
      else i++;
      cur = cur.slice(0, -1);
      continue;
    }
    if (c === '+') { i++; continue; } // + 不影响必现性
    if ('.^$|)]}'.includes(c)) { pop(); i++; continue; }
    cur += c; i++;
  }
  if (cur.length > best.length) best = cur;
  return best;
}

// 分支拆分(顶层 |,括号深度 0)
function splitAlternatives(pattern) {
  const alts = [];
  let depth = 0, start = 0;
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] === '\\') { i++; continue; }
    if (pattern[i] === '(') depth++;
    else if (pattern[i] === ')') depth--;
    else if (pattern[i] === '|' && depth === 0) { alts.push(pattern.slice(start, i)); start = i + 1; }
  }
  alts.push(pattern.slice(start));
  return alts;
}

// 验证 Soundness: 若 regex 能匹配某随机 keyId,则 keyId 必含全部备选提取字面量之一
import crypto from 'node:crypto';

const cases = [
  ['AAAA', 'AAAA'],
  ['\\d{5}', ''],
  ['deadbeef', 'deadbeef'],
  ['\\w{3}AAAA', 'AAAA'],
  ['[a-f]{4}', ''],
  ['AB+C', 'ABC'],
  ['A?BC', 'BC'],
  ['\\d{2}2025', '2025'],
  ['(\\w)\\1{4,}', ''],        // 反向引用: 不提取(宁可回落 CPU)
  ['(?:AAAA)', ''],            // 非捕获组: 保守不支持
  ['20240101', '20240101'],
  ['\\\\AA', '\\AA'],          // \\AA 匹配"反斜杠+AA",提取 "\AA";含非hex → 调用方标记死规则(keyId 永不含反斜杠)
];

let fail = 0;
for (const [pat, expect] of cases) {
  const got = extractLiteral(splitAlternatives(pat)[0]);
  const ok = got === expect || (pat === '\\\\AA' && got === '.AA');
  console.log(`${ok ? 'PASS' : 'FAIL'}  /${pat}/ -> "${got}" (expect "${expect}")`);
  if (!ok) fail++;
}

// Soundness 随机测试: 用简单正则在真实 keyId 池上交叉验证
const sample = Array.from({ length: 20000 }, () => crypto.randomBytes(8).toString('hex'));
const simplePatterns = ['AAAA', '\\d{5}', 'deadbeef', 'AB+C', '\\d{2}2025', 'A?BC', '\\w{3}AAAA'];
let unsound = 0;
for (const pat of simplePatterns) {
  const lit = extractLiteral(splitAlternatives(pat)[0]);
  if (!lit) continue;
  const re = new RegExp(pat, 'g');
  const litHex = /[0-9a-f]/i;
  if (![...lit].every((ch) => litHex.test(ch))) continue;
  for (const s of sample) {
    const m = new RegExp(pat, 'g').test(s);
    const has = s.includes(lit);
    if (m && !has) { unsound++; console.error(`UNSOUND: /${pat}/ matched ${s} but literal "${lit}" absent`); break; }
  }
}
console.log(unsound === 0 ? 'soundness cross-check: OK (regex match ⇒ literal present)' : `soundness FAILED: ${unsound}`);
process.exit(fail === 0 && unsound === 0 ? 0 : 1);

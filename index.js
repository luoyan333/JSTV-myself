/* JSTV 红果短剧独立源 1.0.0, 2026-10-27.
 * GPL-3.0-or-later. PureSign: sunnysky123/hongguo-web, jackotom/hongguo-drama,
 * woshishiq1/drpys. Anonymous registration: qq294716498/HongguoTV-Phone-TV-NoAds.
 * CENC sample indexing adapted from Yswag/xptv-extensions.
 * No account login, user cookies, configuration reads or persistent secrets.
 */
'use strict';
const http=require('http'),https=require('https'),crypto=require('crypto'),zlib=require('zlib');
const CryptoUtil=(()=>{const module={exports:{}};
'use strict';
/**
 * 摘要与对称加密工具（对应原 Java util/Crypto.java，基于 Node crypto）。
 * 提供 hex/unhex/MD5/AES-128-CTR/popcount 等最小能力。
 */
const crypto = require('crypto');

function toBuf(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  return Buffer.from(data);
}

/** 小写十六进制。 */
function hex(data) {
  return toBuf(data).toString('hex');
}

/** 十六进制解码，非法字符/奇数长度直接抛错。 */
function unhex(s) {
  const t = String(s).trim();
  if (t.length % 2 !== 0) throw new Error('十六进制长度必须为偶数');
  if (!/^[0-9a-fA-F]*$/.test(t)) throw new Error('非法十六进制字符');
  return Buffer.from(t, 'hex');
}

/** 大写十六进制（x-ss-stub 需要）。 */
function hexUpper(data) {
  return hex(data).toUpperCase();
}

function md5(data) {
  return crypto.createHash('md5').update(toBuf(data)).digest();
}

/** MD5 大写十六进制，对应 Node createHash('md5').update(d).digest('hex').toUpperCase()。 */
function md5HexUpper(data) {
  return hexUpper(md5(data));
}

function base64Decode(s) {
  return Buffer.from(String(s).trim(), 'base64');
}

/**
 * AES-128-CTR 加解密（同一函数，加解密对称）。
 * @param {Buffer} key 16 字节密钥
 * @param {Buffer} counter 16 字节初始计数器
 * @param {Buffer} data 待处理数据
 */
function aes128Ctr(key, counter, data) {
  if (key.length !== 16) throw new Error('content key 长度非法');
  if (counter.length !== 16) throw new Error('CTR 计数器必须 16 字节');
  const c = crypto.createCipheriv('aes-128-ctr', key, counter);
  return Buffer.concat([c.update(data), c.final()]);
}

/** 32 位无符号整数的二进制 1 的个数（对应 spade 解包的 popcount）。 */
function popcount(x) {
  let v = x >>> 0;
  v = v - ((v >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0f0f0f0f;
  return (v * 0x01010101) >>> 24;
}

module.exports = { hex, unhex, hexUpper, md5, md5HexUpper, base64Decode, aes128Ctr, popcount };

return module.exports;})();
const PureSign=(()=>{const module={exports:{}};
'use strict';
/**
 * 红果 App 接口签名，纯 JS 实现（对应原 Java core/PureSign.java，
 * 不再依赖 unidbg + libmetasec_ml.so）。
 *
 * 移植自 jackotom/hongguo-drama 的 src/native/app-source.js（GPL-3.0），
 * 其签名与 spade 算法改编自 woshishiq1/drpys，经 N3urda/hongguoTV 传递。
 * 原实现用 unidbg 在 x86 上模拟 ARM64 so 计算同样的六个签名头；
 * 此处按同一算法直接计算，字节级对齐：
 *
 *   x-gorgon  : RC4 变体 + 位旋转/位反转后处理
 *   x-khronos : 秒级时间戳
 *   x-ladon   : be32(khronos) 的 base64
 *   x-argus   : le32(khronos) 的 base64
 *   x-helios  : md5 -> 64 位字表 -> 类 Feistel 变换的 base64
 *   x-medusa  : sm3(query) + md5(body) 经 hashF13 分支 -> protobuf 消息
 *               -> xmxor 混淆 -> 逆序 -> 异或 -> AesV3 加密的 base64
 *
 * 用法：sign(url, body) 传入完整 URL（含 query）与请求体，
 * 返回需要合并进请求头的签名字段。
 *
 * 注意：签名对 query 字节级敏感，URL 必须与最终发出的请求完全一致
 * （本模块只读 url 的 '?' 之后部分做 sm3，因此调用方传入什么就签什么）。
 *
 * 移植约定：Java byte[] 为有符号（-128..127），JS 用 Buffer 并在需要处
 * 以 `& 0xff` 取无符号；Java int 的 32 位溢出用 `| 0` 对齐；Java long
 * 的 64 位运算用 BigInt。
 */
const crypto = require('crypto');
const Crypto = CryptoUtil;


// SM3 由 Node 内置 crypto 提供（依赖 OpenSSL >= 1.1.1，Node >= 18 均满足）；
// 不可用时直接抛错，不做降级——x-medusa 签名链路离开 SM3 无法工作。
if (!crypto.getHashes().includes('sm3')) {
  throw new Error('当前 Node 运行时缺少 SM3 算法支持（需 OpenSSL >= 1.1.1），x-medusa 签名链路无法工作');
}

// ==================== 基础位运算（对齐 JS 的 u32 语义） ====================

function rotl(x, n) {
  const k = n & 31;
  return (((x << k) | (x >>> ((32 - k) & 31)))) | 0;
}

function ror(x, n) {
  const k = n & 31;
  return (((x >>> k) | (x << ((32 - k) & 31)))) | 0;
}

/** 8 位循环左移。 */
function rotl8(x) {
  return ((x << 4) | (x >>> 4)) & 255;
}

/** 8 位循环左移 3 位（xmxor 专用，与 rotl8 的移位数不同）。 */
function rotl8_3(x) {
  return ((x << 3) | (x >>> 5)) & 255;
}

/** 反转一个字节的 8 个位。 */
function reverseBits(value) {
  let r = 0;
  for (let i = 0; i < 8; i++) r = (r << 1) | ((value >> i) & 1);
  return r;
}

function readLe32(b, off) {
  return ((b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
    | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24)) | 0;
}

function readBe32(b, off) {
  return (((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
    | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff)) | 0;
}

function putLe32(b, off, v) {
  b[off] = v & 0xff;
  b[off + 1] = (v >>> 8) & 0xff;
  b[off + 2] = (v >>> 16) & 0xff;
  b[off + 3] = (v >>> 24) & 0xff;
}

function putBe32(b, off, v) {
  b[off] = (v >>> 24) & 0xff;
  b[off + 1] = (v >>> 16) & 0xff;
  b[off + 2] = (v >>> 8) & 0xff;
  b[off + 3] = v & 0xff;
}

function le32(v) {
  const b = Buffer.alloc(4);
  putLe32(b, 0, v);
  return b;
}

function be32(v) {
  const b = Buffer.alloc(4);
  putBe32(b, 0, v);
  return b;
}

/** 读 64 位小端无符号（对应 Java readU64Le，语义按无符号位型处理）。 */
function readU64Le(b, off) {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i] & 0xff);
  return BigInt.asUintN(64, v);
}

function putU64Be(b, off, v) {
  const x = BigInt.asUintN(64, v);
  for (let i = 0; i < 8; i++) b[off + i] = Number((x >> BigInt(56 - 8 * i)) & 0xffn);
}

function putU64Le(b, off, v) {
  const x = BigInt.asUintN(64, v);
  for (let i = 0; i < 8; i++) b[off + i] = Number((x >> BigInt(8 * i)) & 0xffn);
}

/** 64 位循环右移（对应 Java Long.rotateRight）。 */
function rotr64(x, n) {
  const v = BigInt.asUintN(64, x);
  const k = BigInt(n & 63);
  if (k === 0n) return v;
  return BigInt.asUintN(64, (v >> k) | (v << (64n - k)));
}

function concat(...parts) {
  return Buffer.concat(parts);
}

/** 对应 Java slice(byte[], from, to)：返回同区间字节（此处用视图即可）。 */
function sliceBytes(b, from, to) {
  return b.subarray(from, to);
}

function xorBytes(a, b) {
  const out = Buffer.from(a);
  for (let i = 0; i < out.length; i++) out[i] = out[i] ^ b[i % b.length];
  return out;
}

function md5(data) {
  return Crypto.md5(data);
}

function sm3(data) {
  return crypto.createHash('sm3').update(data).digest();
}

function b64(data) {
  return data.toString('base64');
}

const EMPTY = Buffer.alloc(0);

// ==================== protobuf 手写编码 ====================

function varint(value) {
  // 仅签路使用非负值（负值一律走 sint 的 zigzag）
  let n = typeof value === 'bigint' ? value : BigInt(value);
  const out = [];
  while (n > 127n) {
    out.push(Number((n & 127n) | 128n));
    n >>= 7n;
  }
  out.push(Number(n));
  return Buffer.from(out);
}

function zigzag(value) {
  return value < 0n ? ((-value) * 2n - 1n) : value * 2n;
}

/** 单个 protobuf 字段。type: string/bytes/message/float/sint/int。 */
function protoField(tag, value, type) {
  if (value === null || value === undefined) return EMPTY;
  if (type === 'string' && value === '') return EMPTY;
  let head;
  let body;
  if (type === 'bytes' || type === 'message') {
    body = value;
    head = concat(varint((BigInt(tag) << 3n) | 2n), varint(body.length));
  } else if (type === 'string') {
    body = Buffer.from(String(value), 'utf8');
    head = concat(varint((BigInt(tag) << 3n) | 2n), varint(body.length));
  } else if (type === 'float') {
    body = Buffer.alloc(4);
    body.writeFloatLE(Number(value), 0);
    head = varint((BigInt(tag) << 3n) | 5n);
  } else {
    const v = BigInt(Math.trunc(Number(value)));
    head = varint(BigInt(tag) << 3n);
    body = varint(type === 'sint' ? zigzag(v) : v);
  }
  return concat(head, body);
}

/** proto([[tag, value, type], ...]) 的紧凑写法。 */
function proto(fields) {
  const parts = [];
  for (const f of fields) {
    const type = f.length > 2 ? String(f[2]) : 'string';
    parts.push(protoField(Number(f[0]), f[1], type));
  }
  return concat(...parts);
}

// ==================== hashF13 家族 ====================

/** getIv：按字节奇偶交替混合的 32 位状态机。 */
function getIv(iv, data) {
  let value = iv;
  for (let i = 0; i < data.length; i++) {
    const d = data[i] & 0xff;
    if ((i & 1) === 0) {
      value = ((value >>> 4) ^ value ^ (value << 6) ^ d) | 0;
    } else {
      value = ~((value >>> 7) ^ value ^ (d | (value << 12)));
    }
  }
  return value;
}

/** sumMd5：取前 12 字节的固定轮混淆，末位或 4 再异或 0x1000000。 */
function sumMd5(data) {
  let check = 0x20220420;
  for (let i = 0; i < 12; i++) {
    const temp = (i & 1) === 0 ? ((check >>> 3) ^ check) : ((check >>> 5) ^ check);
    check = (i & 1) === 0
      ? ((data[i] & 0xff) ^ (check << 7))
      : ((data[i] & 0xff) | (check << 11));
    if ((i & 1) !== 0) check = ~check;
    check = check ^ temp;
  }
  return ((check | 4) ^ 0x1000000) | 0;
}

const BRANCH2_SV = [
  0xa7aefe20, 0x7149f1d6, 0x47e4ca07, 0xe9b58f67, 0x93b924de, 0xc614d0f5, 0x38afe0ef, 0xb2bbad73,
  0xe24444c3, 0x9d3aec9b, 0xdf7b37e4, 0xd8b16d40, 0xf8ac31b8, 0x76b9a90b, 0x31d833ee, 0x953fce64,
  0x353595a4, 0x4609c13b, 0x36925008, 0x8c6d0925, 0x5df5c177, 0x1cfbf52b, 0x8a4fa7f0, 0x114ca35e,
  0x8193f984, 0x7a7a8733, 0x316ab4d5, 0x3c20cfc9, 0xa6d84453, 0x3a18500c, 0x798ec47a, 0x97a76b28,
  0x66c4ff96, 0x51716443, 0x0dd2fc3b, 0xb5696da7, 0xbbeb3ac5, 0x5c53d204, 0xd32608ce, 0x7279b9ec,
  0xf4188ecf, 0xf7d793db, 0x332cc491, 0xab76ae15, 0x9bebe727, 0x18a01384, 0x5be9f8a7, 0x5f90a754,
  0x39b663c0, 0x36673c83, 0x7c92f514, 0x9d7d94d7, 0xe2e8d9aa, 0x5f7e9ea9, 0x7abd4551, 0x569e05da,
  0x40a25632, 0x3df5a9a5, 0xbab37d80, 0x454286dc, 0x3f5d4e78, 0x03d7b75d, 0xb1fe4af7, 0xa5ab26a3];

const BRANCH2_ORDERS = Crypto.unhex(
  '0f0704000908030a060b050d0e010c02'
  + '0f05080c0009020103070e060b0a0d04'
  + '060500070c000a04080f010b0d09020e'
  + '060b02050403080101070a000d0c090e'
  + '0d070e0f0b0208030c0509010004060a'
  + '0d0902060f0b0a040807000c0503010e'
  + '0c090f07060f030e020d0405010b0a00'
  + '0c050a090e0802040407030f01060b00'
  + '0b0f0408020a0700090d06010e03050c'
  + '0b060a0508020c03070f0e090d000104'
  + '0906080f050800040a0b030d01020c0e'
  + '090d0c0604070a03030f00080105020e'
  + '01000d0f090a0b0e0402080703060c05'
  + '01080a0c0f0905060b000304020e070d'
  + '04080f000c0f0e0d0a01060207090503'
  + '040205080d0b0a0606000e0f070c0903'
  + '0a08040f000b01060d0c0709030e0502'
  + '0a070b050f00020e0108030d0c060904'
  + '0d070f08050f06040b0a0e0c09000203'
  + '0d0c020704010b0e0e08060f09050003');

function md5V3Step(kind, a, b, c, d, m, shift, constant) {
  let f;
  if (kind === 0) f = (b & c) | (~b & d);
  else if (kind === 1) f = (b & d) | (c & ~d);
  else if (kind === 2) f = b ^ c ^ d;
  else f = c ^ (b | ~d);
  return (b + rotl((a + f + m + constant) | 0, shift)) | 0;
}

/** MD5 变体：固定轮常量表 + 消息编排表驱动的 64 轮压缩。 */
function md5SumV3(message, countV2, orders, countV1) {
  const sv = new Array(BRANCH2_SV.length);
  for (let i = 0; i < sv.length; i++) sv[i] = ror(BRANCH2_SV[i], countV1);
  const start = [
    ror(0x79e0f2fb, countV2), ror(0xc8b52570, countV2),
    ror(0xebc2f8cd, countV2), ror(0x7c104d93, countV2)];
  const endCount = (countV2 + 6) & 255;
  const end = [
    ror(0x19be4866, endCount), ror(0xe85986b4, endCount),
    ror(0xe19b326e, endCount), ror(0x71d1d7d4, endCount)];
  const m = new Array(16);
  for (let i = 0; i < 16; i++) m[i] = readLe32(message, i * 4);
  let a = start[0]; let b = start[1]; let c = start[2]; let d = start[3];

  const shifts0 = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22];
  const shifts1 = [5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20];
  const shifts2 = [4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23];
  const shifts3 = [6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

  for (let kind = 0; kind < 4; kind++) {
    const shifts = kind === 0 ? shifts0 : kind === 1 ? shifts1 : kind === 2 ? shifts2 : shifts3;
    const offset = kind * 16;
    for (let i = 0; i < 16; i++) {
      const phase = i & 3;
      const mm = m[orders[offset + i] & 0xff];
      const cc = sv[offset + i];
      let next;
      if (phase === 0) next = md5V3Step(kind, a, b, c, d, mm, shifts[i], cc);
      else if (phase === 1) next = md5V3Step(kind, d, a, b, c, mm, shifts[i], cc);
      else if (phase === 2) next = md5V3Step(kind, c, d, a, b, mm, shifts[i], cc);
      else next = md5V3Step(kind, b, c, d, a, mm, shifts[i], cc);
      if (phase === 0) a = next;
      else if (phase === 1) d = next;
      else if (phase === 2) c = next;
      else b = next;
    }
  }
  const ret = Buffer.alloc(16);
  putLe32(ret, 0, (start[0] + a) ^ end[0]);
  putLe32(ret, 4, (start[1] + b) ^ end[1]);
  putLe32(ret, 8, (start[2] + c) ^ end[2]);
  putLe32(ret, 12, (start[3] + d) ^ end[3]);
  return concat(ret, le32(sumMd5(ret)));
}

function branch2F13(iv, querySm3, bodyMd5, tsBytes, khronos) {
  const v = (iv & 13) * 86;
  const ivV0 = ((v >>> 15) & 255) + ((v >>> 8) & 255);
  const n1 = [0x8980f29b, 0xeb549c7f, 0xb08726db, 0xd40cb5e6, 0xe8f559e4][ivV0];
  const countV1 = (n1 + khronos + 1) & 255;
  const countV2 = (n1 + khronos) | 0;
  const shift = (countV2 + 5) & 7;
  const seed = [0x84, 0x96, 0x77, 0x9d, 0xd4, 0x15, 0x0b, 0xf8];
  const pad = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) pad[i] = ((seed[i] | (seed[i] << 8)) >> shift) & 255;
  const input = concat(querySm3, bodyMd5, tsBytes, pad,
    Crypto.unhex('a0010000'));
  const from = ivV0 << 6;
  const to = (ivV0 + 1) << 6;
  const orders = sliceBytes(BRANCH2_ORDERS, from, to);
  return md5SumV3(input, countV2, orders, countV1);
}

/** hashF13：按 iv 低 4 位选分支（0 为主分支，1 不被服务端接受，2 为备用变体）。 */
function hashF13(querySm3, bodyMd5, tsBytes, khronos) {
  const iv = getIv(getIv(getIv(0x20230928, querySm3), bodyMd5), tsBytes);
  const low = iv & 15;
  const ivV0 = (low * 171) >> 9;
  const branch = low - ivV0 * 3;
  if (branch === 2) return branch2F13(iv, querySm3, bodyMd5, tsBytes, khronos);
  if (branch !== 0) {
    return concat(sliceBytes(querySm3, 0, 16), bodyMd5,
      le32(sumMd5(concat(querySm3, bodyMd5))));
  }

  const ivV1List = [0xc4a78580, 0xb3c0fd39, 0xc58c5686, 0xc9aa3ba7, 0xf5a7adf2, 0x963c2ed1];
  const ivV1 = ivV1List[ivV0] | 0;
  const countV1 = (ivV1 + khronos + 1) & 255;
  const countV2 = (ivV1 + khronos) | 0;
  const tt02 = [
    0xebb64faf, 0x07aadcc2, 0xcf3187bf, 0xe01138ff, 0x6d0bfcff, 0x5a30a3be, 0xb41ad638, 0x34180eb8,
    0xf233eb6f, 0xb1a584cc, 0xccc30dc7, 0x47d1db51, 0xd55653de, 0x70a84fa1, 0x57473c12, 0xf76f0288,
    0x2c077f0a, 0xda0dcad0, 0xfbb86f6c, 0xfdc4cf00, 0x688a020d, 0xe676c6a6, 0x8cd6338b, 0x1a3c8d0e,
    0xcce8b06b, 0x6ad0ed0b, 0xa0522717, 0xdc71ac83, 0x2285db71, 0xd5b4dda6, 0x736f8650, 0x6560306c,
    0x617ce2a6, 0xe423417e, 0x0a40e143, 0x544e4032, 0x88dffb2a, 0x716c1ae0, 0x4c467a88, 0x05b23bb3,
    0xe1d0b866, 0xbaa3dcb8, 0xae3374d3, 0xc3381a50, 0x1702f75b, 0xfe6da368, 0xf0b4cf48, 0x4e0ffbb8,
    0x72aad10d, 0x26c53a3d, 0xf2bce0f6, 0xb4557581, 0x4a257fdd, 0x8c3182a2, 0xab0b3b86, 0x3d5dfb14,
    0x4f103634, 0xd37b52d7, 0x444eff16, 0xeb0a33d1, 0x6ca86f6e, 0x0284ba7, 0x08387cfa, 0x5fb37586];
  const tt = new Array(tt02.length);
  for (let i = 0; i < tt.length; i++) tt[i] = ror(tt02[i], countV1);
  const n0 = (countV2 + 2) & 7;
  const seed = [0xfa, 0x45, 0x61, 0xd7];
  // JS: Buffer.from(seed.map(...)) —— seed 仅 4 个元素，pad 为 4 字节
  const pad = Buffer.alloc(seed.length);
  for (let i = 0; i < seed.length; i++) pad[i] = ((seed[i] | (seed[i] << 8)) >> n0) & 255;
  const data = concat(querySm3, bodyMd5, tsBytes, pad, Crypto.unhex('00000000000001a0'));

  const di = new Array((data.length / 4) + 112 + 16).fill(0);
  let diLen = 0;
  for (let i = 0; i + 3 < data.length; i += 4) di[diLen++] = readBe32(data, i);
  const di0 = di[0];
  for (let i = 0; i < 112; i++) {
    const di1 = di[i + 1];
    const di14 = di[i + 14];
    const r1 = rotl(di1, 14) ^ rotl(di1, 25) ^ (di1 >>> 3);
    const r2 = rotl(di14, 13) ^ rotl(di14, 15) ^ (di14 >>> 10);
    di[diLen++] = (di0 + di[i + 9] + r1 + r2) | 0;
  }

  const initRaw = [0x7aba4fc8, 0x67166507, 0x6403fa00, 0x340f512f,
    984304912, 3005047866, 2874125293, 2152413264];
  const init = new Array(8);
  for (let i = 0; i < 8; i++) init[i] = ror(initRaw[i], countV2 & 31);
  const chosenTable = [
    [101, 5, 7, 6, 3, 2, 1, 0, 5, 4, 3],
    [96, 0, 6, 7, 5, 3, 2, 1, 5, 4, 4],
    [96, 7, 6, 2, 1, 4, 0, 5, 4, 3, 5],
    [99, 3, 6, 2, 4, 5, 1, 0, 0, 7, 6],
    [96, 0, 5, 6, 7, 3, 1, 2, 5, 4, 4],
    [100, 2, 0, 3, 5, 4, 6, 7, 2, 1, 5]];
  const chosen = chosenTable[ivV0];
  const d = init.slice();
  for (let i = 0; i < chosen[0]; i++) {
    const base = (ivV1 + i) | 0;
    const n0v = di[base & 127];
    const n1 = ((d[chosen[3]] ^ d[chosen[4]]) & d[chosen[1]]) ^ d[chosen[3]];
    const n2 = rotl(d[chosen[1]], 26) ^ rotl(d[chosen[1]], 21) ^ rotl(d[chosen[1]], 7);
    const n4 = (n0v + n1 + n2 + tt[base & 63] + d[chosen[5]]) | 0;
    const n5 = rotl(d[chosen[2]], 30) ^ rotl(d[chosen[2]], 19) ^ rotl(d[chosen[2]], 10);
    const n6 = (d[chosen[2]] & d[chosen[6]]) | ((d[chosen[2]] | d[chosen[6]]) & d[chosen[7]]);
    const n7 = (n5 + n6) | 0;
    const old = d[chosen[9]];
    // d.unshift(d.pop())：末元素移到队首（循环右移一格）
    const last = d[d.length - 1];
    for (let k = d.length - 1; k >= 1; k--) d[k] = d[k - 1];
    d[0] = last;
    d[chosen[10]] = (n7 + n4) | 0;
    d[chosen[8]] = (old + n4) | 0;
  }
  const ret = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) putBe32(ret, i * 4, (d[i] + init[i]) | 0);
  for (let i = 0; i < 16; i++) ret[i] = ret[i] ^ ret[i + 16];
  return concat(sliceBytes(ret, 0, 16), le32(sumMd5(sliceBytes(ret, 0, 16))));
}

// ==================== x-gorgon ====================

/** RC4 变体（KSA 只赋值不交换，PRGA 异或 s[(y+y)&255]）。 */
function rc4Gorgon(data, key) {
  const s = new Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 255;
    s[i] = s[j];
  }
  const out = Buffer.alloc(data.length);
  let i = 0;
  j = 0;
  for (let k = 0; k < data.length; k++) {
    i += 1;
    const x = s[i];
    j += x;
    const y = s[j & 255];
    s[i] = y;
    out[k] = data[k] ^ s[(y + y) & 255];
  }
  return out;
}

function xGorgon(query, body, timestamp, random) {
  const q4 = sliceBytes(md5(Buffer.from(query, 'utf8')), 0, 4);
  const b4 = body != null && body.length > 0
    ? sliceBytes(md5(body), 0, 4) : Buffer.alloc(4);
  const sdk = le32(67503104);
  const input = concat(q4, b4, Buffer.alloc(4), sdk, be32(timestamp | 0));
  const key = [0x4a, 0x40, 0x16, (random >> 8) & 255, 0x47, 0x6c, 0x01, random & 255];
  const out = rc4Gorgon(input, key);
  for (let i = 0; i < out.length; i++) {
    const value = rotl8(out[i] & 0xff);
    const next = i + 1 < out.length ? (out[i + 1] & 0xff) : (out[0] & 0xff);
    out[i] = (~(reverseBits((next ^ value) & 255) ^ 20)) & 255;
  }
  return Crypto.hex(concat(Crypto.unhex('8404'),
    Buffer.from([random & 255, (random >> 8) & 255, 0x40, 0x01]), out));
}

// ==================== AesV3（medusa 内置的 AES 变体） ====================

const SBOX = Buffer.from(
  '+n0Ia5xZs0sEXznQOEqRmQBnpiCf9U2Ccybu3xhmgzOAAxn72f6uqqmwUsYL83klTni0NqxdGieeiNu9PGPsSRXBMB/cuFbUbM3KCUPINaPvHvSW0vwOcnuUhNHqRVpiAj/TEoE0K91+5ijypUYTATsh9mE3KSoN7Yyvv51cuyR2D3XkU4nhmI2xmmVwT1RMWKtub4sjxAcRDLrPoKSO2AU9FLLadMPX577Wf95IFj6FkKFVt3dCIsmGUC4X+WQxLJvxbRxEaOPpqJOXyzJX6+Vxaq3AzMfF/WAdoi1Hp+JRaV56zgpBtpWP97mH4DoGEIq1+FvV8LyS/3wvwugbQOwb2r26mJEMsiuDQTRn+wrYdrVGBVlhI3WQhyrjUBVMrLF5667llUcEaPCGPVGLD8qO5LlO8hKCvA7V9+8oJc9bXelqVQLhM76T5/WtnT45JKji+hdX0HoNCDDWuKON/QeaxB5uImSX0h2wv0VmP2zd2yeApxHcpsVS+MC2yFwAc2B7oBkTqsk1SEvTpM2fmfMQREBUfin0Bh+iq6EvPPavhWI2IX9e3yAas7Tm/3KEj2UmlFp36kN4x0rMLBRrxuh0U/zUHM4xcAMYjJY4MonxOl/X+alpt2M3WMI7w3HLnpIBigtNiJu7T21v4P6lSd5WFgntnMEt7oF92XzRLkJbTcGmXepE/UVOG6E/0YnhfS+q26utWcuxzpooyeD2cDlK1/8w9d28VzsRjbLuALbmGlp8+d7EzS6Au7lMpZ+ECMZvQmzwJ+eLOpxR+2chdUExp8ogQyq3v9l68rX4jCwjg0+PYKAEEzcU4wHFY2ZcdIHfWL1okD3SszT0GZMyKdZJrg1L2AeerB4tC0C4crp2EHGo5FYdSP7lwkeR2ocmnR+Ia8CYviUJlzOjhRZef9xuVOn3qcjow3fQgivsAmKKkg4+sA8F8/GWeDiGNhg8JM8KtFPMYWWkx5TVFX5t73kiNRJqjlIGVXtGZFCV4gzt0xcDopuZ6xz8r9Rzafpf9ywev8jh8592gHFIqpStZPuJxmDDMrNN0uBE3V+oscdoIzTJbRJ/t+sVvqnReJOgDJKk10fjisJwqyZBmnmn2BSFj8BvVtCMEbkuPOKdzw7eA11GPs04Qw8zWtkaZWwiO/wwpojqN6K0jY5RnNZA7vn4hPSul+nKCkVnVwQvg1zVxcSCtqORmB9KrJaBbssbCQivGJVJfVTt+hYxOtq4ZvWl8f4QAQZ0zGPffCgl9s6yT4vlvIdpu4YhBwA25wtQWZsc6GJYGWHyvSdeuh3mmUI9DSq13Fsp8C1MU3tqc04/df9LoTUXVXI5INOw/e8C7Hd+5CvbkMEFnnrUUmskEw==',
  'base64');

/** JS 语义：越界读返回 0（undefined 在位运算中等价于 0）。 */
function aesSrc(data, idx) {
  return idx < data.length ? (data[idx] & 0xff) : 0;
}

function aesPut(out, idx, value) {
  if (idx >= 0 && idx < out.length) out[idx] = value & 0xff;
}

function aesMatrix(bytes) {
  const rows = new Array(4);
  for (let i = 0; i < 4; i++) {
    rows[i] = new Array(4);
    for (let j = 0; j < 4; j++) rows[i][j] = bytes[i * 4 + j] & 0xff;
  }
  return rows;
}

function aesFlat(rows) {
  const b = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) b[i * 4 + j] = rows[i][j] & 0xff;
  }
  return b;
}

function aesXt(x) {
  return ((x << 1) ^ ((x & 128) !== 0 ? 0x1b : 0)) & 255;
}

function aesMix(rows) {
  for (let i = 0; i < 4; i++) {
    const t = rows[0][i] ^ rows[1][i] ^ rows[2][i] ^ rows[3][i];
    const u = rows[0][i];
    rows[0][i] ^= t ^ aesXt(rows[0][i] ^ rows[1][i]);
    rows[1][i] ^= t ^ aesXt(rows[1][i] ^ rows[2][i]);
    rows[2][i] ^= t ^ aesXt(rows[2][i] ^ rows[3][i]);
    rows[3][i] ^= t ^ aesXt(rows[3][i] ^ u);
  }
}

/** AES 变体：S 盒按 khronos 选段、行/列换用查表、密钥扩展 12 组。 */
class AesV3 {
  constructor(key, khronos) {
    this.wordSize = khronos & 3;
    this.box = sliceBytes(SBOX, this.wordSize * 256, (this.wordSize + 1) * 256);
    const con2Table = [[1, 0, 2, 3], [2, 0, 3, 1], [0, 1, 3, 2], [1, 0, 2, 3]];
    const orderTable = [
      [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3],
      [0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11],
      [0, 9, 14, 7, 4, 13, 2, 11, 8, 1, 6, 3, 12, 5, 10, 15],
      [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3]];
    this.con2 = con2Table[this.wordSize];
    this.order = orderTable[this.wordSize];
    const init = [0xca025ddc, 0x823dc546, 0xc9420583, 0xc298225f][this.wordSize];
    const initial = Buffer.alloc(16);
    for (let i = 0; i < 4; i++) putLe32(initial, i * 4, init);
    const mk = xorBytes(initial, key);
    const expanded = concat(mk, Buffer.alloc(32));
    let rounds = 8;
    for (let i = 4; i < 12; i++) {
      const at = 4 * (i - 1);
      let a = expanded[at] & 0xff; let b = expanded[at + 1] & 0xff;
      let c = expanded[at + 2] & 0xff; let d = expanded[at + 3] & 0xff;
      if ((i & 3) === 0) {
        const t = ((init >>> (rounds & 24)) ^ (this.box[b] & 0xff)) & 255;
        b = this.box[c] & 0xff;
        c = this.box[d] & 0xff;
        d = this.box[a] & 0xff;
        a = t;
      }
      rounds += 2;
      expanded[at + 4] = (a ^ (expanded[at - 12] & 0xff)) & 0xff;
      expanded[at + 5] = (b ^ (expanded[at - 11] & 0xff)) & 0xff;
      expanded[at + 6] = (c ^ (expanded[at - 10] & 0xff)) & 0xff;
      expanded[at + 7] = (d ^ (expanded[at - 9] & 0xff)) & 0xff;
    }
    this.keys = new Array(12);
    for (let i = 0; i < 12; i++) {
      this.keys[i] = new Array(4);
      for (let j = 0; j < 4; j++) this.keys[i][j] = expanded[i * 4 + j] & 0xff;
    }
  }

  add(rows, key) {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) rows[i][j] ^= key[i][j];
    }
  }

  addCon(rows, ks) {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) rows[i][j] ^= ks[i][this.con2[j]];
    }
  }

  sub(rows) {
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) rows[i][j] = this.box[rows[i][j]] & 0xff;
    }
    const old = new Array(4);
    for (let i = 0; i < 4; i++) old[i] = rows[i].slice();
    for (let i = 0; i < 4; i++) rows[i] = old[this.con2[i]];
  }

  shift(rows) {
    const b = aesFlat(rows);
    for (let i = 0; i < 16; i++) rows[(i / 4) | 0][i % 4] = b[this.order[i]] & 0xff;
  }

  shiftCon(rows) {
    const old = new Array(4);
    for (let i = 0; i < 4; i++) old[i] = rows[i].slice();
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) rows[i][j] = old[i][this.con2[j]];
    }
  }

  block(value) {
    const rows = aesMatrix(value);
    const k0 = this.subKeys(0);
    this.addCon(rows, k0);
    for (let i = 1; i < 3; i++) {
      this.sub(rows);
      this.shift(rows);
      if (i === 1) {
        this.shiftCon(rows);
        aesMix(rows);
      }
      this.addCon(rows, this.subKeys(i * 4));
    }
    this.add(rows, this.subKeys(4));
    return aesFlat(rows);
  }

  subKeys(from) {
    const out = new Array(4);
    for (let i = 0; i < 4; i++) out[i] = this.keys[from + i].slice(0, 4);
    return out;
  }

  /** 加密：明文具化到 32 字节 -> CBC 两轮 -> 按 key 逐位回填源数据，末尾缀 key 末字节。 */
  encrypt(data, iv) {
    const plaintext = Buffer.alloc(32);
    for (let i = 0; i < 31; i++) {
      const at = i * 8;
      const n0 = (aesSrc(data, at) >> 4) & 2;
      const n1 = n0 | (aesSrc(data, at + 1) & 64);
      const n2 = n1 | ((aesSrc(data, at + 2) >> 2) & 1);
      const n3 = n2 | ((aesSrc(data, at + 3) << 3) & 128);
      const n4 = n3 | ((aesSrc(data, at + 4) >> 1) & 4);
      const n5 = n4 | ((aesSrc(data, at + 5) << 3) & 16);
      const n6 = n5 | ((aesSrc(data, at + 6) << 5) & 32);
      plaintext[i] = (n6 | ((aesSrc(data, at + 7) >> 4) & 8)) & 0xff;
    }
    plaintext[31] = 1;
    const blocks = [];
    let previous = Buffer.from(iv);
    for (let i = 0; i < plaintext.length; i += 16) {
      const value = this.block(xorBytes(sliceBytes(plaintext, i, i + 16), previous));
      blocks.push(value);
      previous = value;
    }
    const key = concat(...blocks);
    const out = Buffer.from(data);
    for (let i = 0; i < 31; i++) {
      const at = i * 8;
      const k = key[i] & 0xff;
      // JS 语义：越界读写均静默忽略，故读用 aesSrc()、写用 aesPut()
      aesPut(out, at, (aesSrc(out, at) & 0xdf) | ((k << 4) & 32));
      aesPut(out, at + 1, (aesSrc(out, at + 1) & 0xbf) | (k & 64));
      aesPut(out, at + 2, (aesSrc(out, at + 2) & 0xfb) | ((k << 2) & 4));
      aesPut(out, at + 3, (aesSrc(out, at + 3) & 0xef) | ((k >> 3) & 16));
      aesPut(out, at + 4, (aesSrc(out, at + 4) & 0xf7) | ((k + k) & 8));
      aesPut(out, at + 5, (aesSrc(out, at + 5) & 0xfd) | ((k >> 3) & 2));
      aesPut(out, at + 6, (aesSrc(out, at + 6) & 0xfe) | ((k >> 5) & 1));
      aesPut(out, at + 7, (aesSrc(out, at + 7) & 0x7f) | ((k << 4) & 128));
    }
    return concat(sliceBytes(key, key.length - 1, key.length), out);
  }
}

// ==================== xmxor / keyHash / medusa / helios ====================

/** xmxor：按 key 表逐字节混淆 + 三段尾部修正。 */
function xmxor(data, key) {
  const encoded = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    const at = (i * 4) & 28;
    const d0 = key[at] & 0xff;
    const d1 = key[at + 1] & 0xff;
    let d2 = (rotl8(data[i] & 0xff) + d0);
    d2 = (~d2) ^ d1;
    d2 = rotl8_3(d2 & 0xff);
    d2 = (d2 + d1) & 255;
    d2 = (d2 ^ d0) & 255;
    encoded[data.length - i - 1] = (~d2) & 255;
  }
  const last = (encoded[encoded.length - 1] ^ encoded[encoded.length - 2]) & 255;
  const first = encoded[0] & 0xff;
  encoded[0] = ((~last) + first) & 255;
  encoded[1] = ((encoded[0] ^ encoded[encoded.length - 1] ^ 254) + encoded[1]) & 255;
  encoded[2] = (encoded[2] + (((last - first) ^ rotl8_3(encoded[1] & 0xff)) ^ 2)) & 255;
  for (let i = 0; i < encoded.length - 4; i++) {
    const temp = (rotl8_3(encoded[i + 2] & 0xff) ^ encoded[i + 1] ^ (i + 3));
    encoded[i + 3] = ((~temp) + encoded[i + 3]) & 255;
  }
  encoded[encoded.length - 1] = (encoded[encoded.length - 1] ^ encoded[encoded.length - 2]) & 255;
  let sum = 0;
  for (let i = 0; i < encoded.length - 1; i++) sum += encoded[i + 1] & 0xff;
  encoded[0] = ((encoded[0] ^ encoded[1]) + sum) & 255;
  return encoded;
}

/** keyHash：signKey || le32(random) || signKey 的 SM3，附一个由 random 派生的 4 字节种子。 */
function keyHash(signKey, random) {
  const hash = sm3(concat(signKey, le32(random), signKey));
  const d1 = (random >> 16) & 255;
  let d2 = (((d1 << 11) | (random >>> 24)) ^ (d1 >> 5) ^ d1);
  d2 = ~d2;
  return [hash, le32(d2)];
}

const MEDUSA_SIGN_KEY = Crypto.unhex(
  '8ebdfa3806ecc5cee79423e6029ed82540bc2218bb7eaef71cb691f7aa8aa2f5');
const MEDUSA_AES_KEY = Crypto.unhex('f1593376766ea98d34f31b057a9d5be4');
const MEDUSA_AES_IV = Crypto.unhex('1fe109a4125283f418de9e051a969e12');
const MEDUSA_MAGIC16 = Crypto.unhex('f7e85ffad7d7dc3bd62ac87057cf6118');
const MEDUSA_MAGIC8 = Crypto.unhex('4001000000000000');

/** 进程级 nonce（18 随机字节的 base64url）。 */
const PROCESS_NONCE = crypto.randomBytes(18).toString('base64url');
const PROCESS_STARTED = Date.now();

function randomBytes(n) {
  return crypto.randomBytes(n);
}

/** 对应 Java RND.nextInt(n)：返回 [0, n) 的整数。 */
function rndInt(n) {
  return crypto.randomInt(n);
}

/** 对应 Java RND.nextInt()：返回有符号 32 位整数。 */
function rndInt32() {
  return crypto.randomBytes(4).readInt32BE(0);
}

/**
 * 设备信息 protobuf。与 jackotom 参考实现保持一致：字段 30-36 为固定设备值
 * （25053RT47C / Redmi / Xiaomi），不跟随 query 参数，仅 deviceId/version 外部传入。
 */
function deviceProto(deviceId, version) {
  return proto([
    [1, 1, 'sint'], [2, 2, 'sint'], [3, '8662'], [4, deviceId],
    [5, PROCESS_NONCE], [6, '!noperm!'], [7, -888888, 'sint'], [8, -888888, 'sint'],
    [9, 3, 'sint'], [10, -888888, 'sint'], [11, '!notset!'],
    [12, 'Asia/Shanghai,8'], [13, 'zh_CN'], [14, 4, 'sint'],
    [16, 0, 'float'], [17, 0, 'float'], [18, 0, 'float'], [19, 0, 'float'],
    [20, 0, 'float'], [21, 0, 'float'], [22, '16'], [23, 41, 'sint'],
    [24, 36, 'sint'], [25, PROCESS_STARTED, 'sint'], [26, PROCESS_STARTED, 'sint'],
    [27, PROCESS_STARTED, 'sint'], [28, PROCESS_STARTED, 'sint'], [29, -1, 'sint'],
    [30, '25053RT47C'], [31, 'Redmi'], [32, '25053RT47C'], [33, '25053RT47C'],
    [34, 'Xiaomi'], [35, 'Redmi'], [36, 'Redmi'], [38, 31, 'sint']]);
}

/** 构造 x-medusa。 */
function buildMedusa(url, body, khronos, deviceId, version) {
  const bodyMd5 = body != null && body.length > 0 ? md5(body) : Buffer.alloc(16);
  const query = queryOf(url);
  const querySm3 = sm3(Buffer.from(query, 'utf8'));
  const ts = le32(khronos | 0);
  const queryBodyTs = hashF13(querySm3, bodyMd5, ts, khronos);

  const messageRand = randomBytes(4);
  const messageRandU = readLe32(messageRand, 0) >>> 0;
  const envLaunch = 100 + rndInt(21);
  const envPid = 10001 + rndInt(2000);
  const env = proto([
    [1, envLaunch, 'sint'], [2, 146331399, 'sint'], [3, 146331396, 'sint'],
    [5, 7, 'sint'], [6, 'v04.06.04.03-bugfix'], [7, envPid, 'sint'],
    [12, deviceProto(deviceId, version), 'message'],
    [13, proto([
      [1, Math.floor(Date.now() / 1000), 'sint'],
      [2, -2, 'sint'], [4, 200, 'sint']]), 'message'],
    [14, version]]);
  const queryHash = sm3(concat(Buffer.from(query, 'utf8'), bodyMd5,
    Buffer.from('none', 'utf8')));

  const nested = proto([
    [1, 111, 'sint'], [2, 10, 'sint'], [3, 694367, 'sint'], [5, 586952199, 'sint']]);
  const message = proto([
    [1, MEDUSA_MAGIC16, 'bytes'], [2, 3, 'sint'], [3, messageRandU, 'sint'],
    [4, '8662'], [5, deviceId], [6, '1588093228'], [7, version],
    [8, 'v04.06.04-ml-android'], [9, 67503104, 'sint'],
    [10, MEDUSA_MAGIC8, 'bytes'], [12, khronos, 'sint'],
    [13, queryBodyTs, 'bytes'], [14, sliceBytes(querySm3, 0, 6), 'bytes'],
    [15, nested, 'message'], [16, PROCESS_NONCE], [17, khronos, 'sint'],
    [19, queryHash, 'bytes'], [20, 'none'], [21, 312, 'sint'],
    [23, env, 'message'],
    [24, '{"cmr":16777216,"cmr2":16777216,"un_h":1879194040,"vpn":0,'
    + '"kd":0,"fkd":3672518972,"pd":-1872573247,"dyn":"",'
    + '"do":0,"tk":true}']]);

  const random = rndInt32();
  const hs = keyHash(MEDUSA_SIGN_KEY, random);
  const hash = hs[0];
  const seed = hs[1];
  let transformed = xmxor(message, hash);
  transformed = concat(MEDUSA_MAGIC8, transformed);
  // 整体逆序
  for (let i = 0, j = transformed.length - 1; i < j; i++, j--) {
    const t = transformed[i];
    transformed[i] = transformed[j];
    transformed[j] = t;
  }
  for (let i = 0; i < transformed.length; i++) {
    transformed[i] = (transformed[i] ^ seed[(~i) & 3]) & 0xff;
  }
  const check = (((querySm3[0] & 63) << 14) | 0x18000001 | ((queryBodyTs[0] & 63) << 8)) | 0;
  const xmRand = rndInt32();
  const packed = concat(Buffer.from([0x35]), le32(xmRand), le32(check), transformed,
    Buffer.from([(random >> 16) & 255, (random >> 24) & 255]));
  const encrypted = new AesV3(MEDUSA_AES_KEY, khronos).encrypt(packed, MEDUSA_AES_IV);
  const versionBytes = Crypto.unhex('03000000f7e85ffad7d7dc3bd62ac87057cf6118');
  const prefix = Buffer.alloc(20);
  for (let i = 0; i < 20; i += 4) {
    // JS: u32(version.readUInt32LE(i) ^ khronos) 后 writeUInt32LE
    putLe32(prefix, i, (readLe32(versionBytes, i) ^ (khronos | 0)));
  }
  return b64(concat(prefix,
    Buffer.from([random & 255, (random >> 8) & 255, 0, 1]), encrypted));
}

/** helios：md5 ASCII 化 -> 64 位字表 -> 34 轮扩展 -> 分组类 Feistel。 */
function helios(khronos) {
  return heliosWith(khronos, rndInt32());
}

/** 可注入 random 的 helios（默认重载用 rndInt32()）。 */
function heliosWith(khronos, random) {
  const digest = md5(concat(le32(random), Buffer.from('8662', 'utf8')));
  const hex = digest.toString('hex');
  const ascii = Buffer.from(hex, 'ascii');
  const words = new Array(4);
  for (let i = 0; i < 4; i++) words[i] = readU64Le(ascii, i * 8);

  // JS: words.splice(0,2) 后每轮 push 一个、shift 一个，队列恒长 2。
  // 用双端队列精确模拟：b8 始终取「最早入队未消费」的元素。
  const queue = [words[2], words[3]];
  let b0 = words[0];
  let b8 = words[1];
  const table = new Array(35);
  table[0] = words[0];
  for (let i = 0; i < 34; i++) {
    let x8 = BigInt.asUintN(64, rotr64(b8, 8) + b0);
    x8 = BigInt.asUintN(64, x8 ^ BigInt(i));
    queue.push(x8);
    x8 = BigInt.asUintN(64, x8 ^ rotr64(b0, 61));
    table[i + 1] = x8;
    b0 = x8;
    b8 = queue.shift();
  }
  const text = String(khronos) + '-1588093228-8662';
  const tb = Buffer.from(text, 'utf8');
  const padLen = Math.floor((tb.length + 1 + 15) / 16) * 16;
  const pad = Buffer.alloc(padLen);
  pad.fill((16 - (tb.length % 16)) & 0xff);
  tb.copy(pad, 0);

  const output = [];
  for (let at = 0; at < pad.length; at += 16) {
    let a = readU64Le(pad, at);
    let b = readU64Le(pad, at + 8);
    for (let i = 0; i < 34; i++) {
      b = BigInt.asUintN(64, table[i] ^ BigInt.asUintN(64, a + rotr64(b, 8)));
      a = BigInt.asUintN(64, b ^ rotr64(a, 61));
    }
    const block = Buffer.alloc(16);
    // JS: block.writeBigUInt64LE —— 小端写入
    putU64Le(block, 0, a);
    putU64Le(block, 8, b);
    output.push(block);
  }
  const all = [le32(random), ...output];
  return b64(concat(...all));
}

// ==================== 分支判定与入口 ====================

/** 与 hashF13 相同的分支计算；branch==1 时服务端不认，调用方应抖动 _rticket 避开。 */
function branchOf(url, body, khronos) {
  const bodyMd5 = body != null && body.length > 0 ? md5(body) : Buffer.alloc(16);
  const q = sm3(Buffer.from(queryOf(url), 'utf8'));
  const iv = getIv(getIv(getIv(0x20230928, q), bodyMd5), le32(khronos | 0));
  const low = iv & 15;
  return low - (((low * 171) >> 9) * 3);
}

function queryOf(url) {
  const i = url.indexOf('?');
  return i < 0 ? '' : url.substring(i + 1);
}

/**
 * 计算一组签名头。
 *
 * @param {string} url  完整 URL（含 query），必须与最终请求一致
 * @param {Buffer|null} body 请求体字节；GET 传 null
 * @param {number} [khronos] 可选的秒级时间戳；缺省取当前时间
 * @returns {object} 需要合并进请求头的字段（x-gorgon / x-khronos / x-ladon / x-argus / x-helios / x-medusa）
 */
function sign(url, body, khronos) {
  const ts = (khronos === undefined || khronos === null)
    ? Math.floor(Date.now() / 1000) : khronos;
  const gorgonRandom = rndInt(65536);
  const query = queryOf(url);
  const out = {};
  out['x-gorgon'] = xGorgon(query, body, ts, gorgonRandom);
  out['x-khronos'] = String(ts);
  out['x-ladon'] = b64(be32(ts | 0));
  out['x-argus'] = b64(le32(ts | 0));
  out['x-helios'] = helios(ts);
  out['x-medusa'] = buildMedusa(url, body, ts,
    paramOf(query, 'device_id', '0'),
    paramOf(query, 'version_name', '7.1.3.32'));
  return out;
}

function paramOf(query, key, fallback) {
  for (const kv of query.split('&')) {
    const eq = kv.indexOf('=');
    if (eq <= 0) continue;
    if (kv.substring(0, eq) === key) {
      const v = kv.substring(eq + 1);
      if (v.length > 0) return v;
    }
  }
  return fallback;
}

module.exports = { sign, branchOf };

return module.exports;})();
'use strict';
const REG_CONSTANTS=Buffer.from([77,212,194,230,184,49,98,9,14,82,179,199,166,115,59,164,28,178,70,43,130,154,181,138,25,107,57,219,87,23,117,36,244,155,175,127,8,232,214,141,38,167,46,55,193,169,90,47,31,5,165,24,146,174,242,148,151,50,182,42,56,170,221,88]);
async function registerAnonymous(){
 const id=()=>crypto.randomBytes(16).toString('hex'),now=Date.now();
 const header={display_name:'红果免费短剧',aid:8662,channel:'69310258a',package:'com.phoenix.read',version_code:73932,app_version:'7.3.9.32',sdk_version:'3.7.0-rc.34-fanqie-xiaoshuo',sdk_target_version:29,git_hash:'3a88f4e',release_build:'b5e187f',os:'Android',os_version:'16',os_api:36,device_model:'25053RT47C',device_brand:'Redmi',device_manufacturer:'Xiaomi',cpu_abi:'arm64-v8a',density_dpi:520,display_density:'mdpi',resolution:'1280x2772',language:'zh',timezone:8,access:'wifi',carrier:'CHINA MOBILE',mcc_mnc:'46000',rom:'BP2A.250605.031.A3',rom_version:'release-keys',cdid:id(),sig_hash:'56a962410c494bbaf0b58dba20cae56f',openudid:crypto.randomBytes(8).toString('hex'),clientudid:id(),region:'CN',tz_name:'Asia/Shanghai',tz_offset:28800,sim_region:'cn',sim_serial_number:[],oaid_may_support:false,req_id:id(),device_platform:'android',custom:{account_region_src:'fallback',host_bit:64,account_region:'cn',dragon_device_type:'phone'},pre_installed_channel:'',apk_first_install_time:now,is_system_app:0,sdk_flavor:'china',guest_mode:0};
 const raw=Buffer.from(JSON.stringify({magic_tag:'ss_app_log',header,_gen_time:now})),gz=zlib.gzipSync(raw),seed=crypto.randomBytes(32),sha=x=>crypto.createHash('sha512').update(x).digest(),km=sha(Buffer.concat([sha(seed),REG_CONSTANTS])),plain=Buffer.concat([sha(gz),gz]),cipher=crypto.createCipheriv('aes-128-cbc',km.subarray(0,16),km.subarray(16,32)),body=Buffer.concat([Buffer.from([0x74,0x63,0x05,0x10,0,0]),seed,cipher.update(plain),cipher.final()]);
 const url='https://log5-applog-lf.fqnovel.com/service/2/device_register/?tt_data=a&cronet_version=8d40f833_2026-03-03&ttnet_version=4.2.243.31-douyin&use_store_region_cookie=1';
 const r=await request(url,{method:'POST',body,headers:{'Content-Type':'application/octet-stream;tt-data=a','Log-Encode-Type':'gzip','X-SS-DP':'8662','X-SS-Req-Ticket':String(now),'X-Vc-Bdturing-Sdk-Version':'4.0.3.cn','Lc':'101','Sdk-Version':'2','Passport-Sdk-Version':'5051452','X-Neptune':'-8|50:51:59:30:40:47:49:39','X-SS-STUB':crypto.createHash('md5').update(body).digest('hex').toUpperCase(),'User-Agent':'com.phoenix.read/73932 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3)'},timeout:12000});
 const text=r.data.toString();if(!text)throw Error('anonymous registration returned empty response');
 const x=JSON.parse(text.replace(/("(?:device_id|install_id)"\s*:\s*)(\d{16,})/g,'$1"$2"'));
 const did=String(x.device_id_str||x.device_id||''),iid=String(x.install_id_str||x.install_id||'');
 if(!/^\d{10,24}$/.test(did)||!/^\d{10,24}$/.test(iid)||!Number(did)||!Number(iid))throw Error('anonymous registration did not issue valid device identity');
 return {device_id:did,install_id:iid};
}


const BASE='https://hongguoduanju.com',PREFIX='/spider/hongguo_local/3';
const WEB_UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36';
const APP_UA='com.phoenix.read/73532 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3)';
const agent=new https.Agent({keepAlive:true,maxSockets:8});
let server,identityPromise=null;const pageCache=new Map(),mediaCache=new Map();
function request(url,opts={},redirects=0){
 return new Promise((resolve,reject)=>{
  const u=new URL(url);if(!['https:','http:'].includes(u.protocol))return reject(Error('不支持的地址协议'));
  const mod=u.protocol==='https:'?https:http;
  const req=mod.request(u,{method:opts.method||'GET',agent:u.protocol==='https:'?agent:undefined,headers:{'User-Agent':WEB_UA,'Accept-Encoding':'gzip, deflate, br',...opts.headers}},res=>{
   if([301,302,303,307,308].includes(res.statusCode)&&res.headers.location){res.resume();if(redirects>=3)return reject(Error('跳转过多'));return request(new URL(res.headers.location,u).href,opts,redirects+1).then(resolve,reject)}
   const chunks=[];let size=0,limit=opts.limit||12*1024*1024;
   res.on('data',c=>{size+=c.length;if(size>limit){req.destroy(Error('响应超出限制'));return}chunks.push(c)});
   res.on('error',reject);res.on('end',()=>{try{let data=Buffer.concat(chunks);const enc=res.headers['content-encoding'];if(enc==='gzip')data=zlib.gunzipSync(data);else if(enc==='br')data=zlib.brotliDecompressSync(data);else if(enc==='deflate')data=zlib.inflateSync(data);if(data.length>limit)return reject(Error('响应超出限制'));resolve({status:res.statusCode,headers:res.headers,data})}catch(e){reject(Error('响应解码失败'))}});
  });
  req.setTimeout(opts.timeout||15000,()=>req.destroy(Error('上游请求超时')));req.on('error',reject);
  if(opts.signal){if(opts.signal.aborted){req.destroy(Error('请求已取消'));return}const abort=()=>req.destroy(Error('请求已取消'));opts.signal.addEventListener('abort',abort,{once:true});req.on('close',()=>opts.signal.removeEventListener('abort',abort))}
  req.end(opts.body);
 });
}
function parseJSON(text){return JSON.parse(text.replace(/("(?:series_id|series_id_str|device_id|install_id|book_id|video_id|vid)"\s*:\s*)(\d{16,})/g,'$1"$2"'))}
async function anonymousIdentity(){if(!identityPromise)identityPromise=registerAnonymous().catch(e=>{identityPromise=null;throw e});return identityPromise}
async function api(path,payload,extra={}){
 const dev=await anonymousIdentity(),body=payload==null?null:Buffer.from(JSON.stringify(payload));
 const qs=new URLSearchParams({aid:'8662',app_name:'novelread',version_code:'73532',version_name:'7.3.5.32',manifest_version_code:'73532',update_version_code:'73532',channel:'update_64',device_platform:'android',os:'android',ssmix:'a',device_type:'25053RT47C',device_brand:'Redmi',language:'zh',os_api:'36',os_version:'16',resolution:'1280*2772',dpi:'520',ac:'wifi',device_id:dev.device_id,iid:dev.install_id,...extra});qs.sort();
 const ts=Math.floor(Date.now()/1000);qs.set('_rticket',String(Date.now()));let url;
 for(let n=0;n<24;n++){url='https://api5-normal-sinfonlineb.fqnovel.com'+path+'?'+qs; if(PureSign.branchOf(url,body,ts)!==1)break;qs.set('_rticket',String(Number(qs.get('_rticket'))+1))}
 const headers={'User-Agent':APP_UA,Accept:'application/json','Content-Type':'application/json; charset=utf-8','X-XS-From-Web':'0','Sdk-Version':'2','X-SS-Req-Ticket':String(Date.now()),...(body?{'X-SS-STUB':crypto.createHash('md5').update(body).digest('hex').toUpperCase()}:{}),...PureSign.sign(url,body,ts)};
 for(let n=0;n<3;n++){const r=await request(url,{method:body?'POST':'GET',headers,body,timeout:12000});if(r.status!==200)throw Error('播放接口 HTTP '+r.status);if(r.data.length){const x=parseJSON(r.data.toString());if(Number(x.code||x.Code||0)!==0)throw Error('播放接口业务错误 '+(x.code||x.Code));return x}if(n<2)await new Promise(r=>setTimeout(r,300*(n+1)))}
 throw Error('播放接口返回空内容，请稍后重试');
}
function routerData(html){let p=html.indexOf('_ROUTER_DATA');if(p<0)throw Error('官网页面结构已变化');p=html.indexOf('{',p);let depth=0,quote=false,escape=false;for(let i=p;i<html.length;i++){const c=html[i];if(quote){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quote=false}else if(c==='"')quote=true;else if(c==='{')depth++;else if(c==='}'&&!--depth)return parseJSON(html.slice(p,i+1))}throw Error('官网页面内容不完整')}
async function page(path){const key=path,old=pageCache.get(key);if(old&&Date.now()-old.time<180000)return old.data;const r=await request(BASE+path,{headers:{Referer:BASE+'/'}});if(r.status!==200)throw Error('官网 HTTP '+r.status);const data=routerData(r.data.toString()).loaderData||{};if(pageCache.size>=32)pageCache.delete(pageCache.keys().next().value);pageCache.set(key,{time:Date.now(),data});return data}
function card(row){const v=row.video_data||row;return {vod_id:String(v.series_id||v.seriesId||''),vod_name:String(v.series_name||v.series_title||v.title||row.name||''),vod_pic:String(v.series_cover||v.cover||''),vod_remarks:v.episode_cnt?'全'+v.episode_cnt+'集':v.episodeCount?'全'+v.episodeCount+'集':''}}
const categories=[{type_id:'real-drama',type_name:'真人短剧'},{type_id:'comic-drama',type_name:'漫剧'},{type_id:'ai-drama',type_name:'AI剧'}];
const animationGenres=[['热门',''],['脑洞','creative'],['玄幻','fantasy'],['剧情','drama'],['末世','apocalypse'],['豪门','wealthy-family'],['奇幻','wonder'],['科幻','sci-fi'],['冒险','adventure']];
const genres=[['热门',''],['玄幻','fantasy'],['逆袭','comeback'],['都市','urban'],['爱情','romance'],['年代','period'],['家庭','family'],['萌宝','cute-kids']];
async function category(body){const kind=categories.some(c=>c.type_id===body.id)?body.id:'real-drama',pg=Math.max(1,Number(body.page)||1),slug=String(body.filters?.class||'');if(slug&&!/^[a-z-]{1,40}$/.test(slug))throw Error('分类无效');const data=await page('/category/'+kind+(slug?'/'+slug:'')+'?page='+pg),value=data.category_$||data.category_page||Object.values(data).find(v=>v&&Array.isArray(v.recommendList))||{};const list=(value.recommendList||value.categoryData?.recommendList||[]).map(card).filter(v=>v.vod_id&&v.vod_name);return {list,page:pg,pagecount:Number(value.pagination?.totalPages)||pg,limit:list.length,total:Number(value.pagination?.total)||list.length}}
async function home(){const filters={};for(const c of categories)filters[c.type_id]=[{key:'class',name:'类型',init:'',value:(c.type_id==='real-drama'?genres:animationGenres).map(([n,v])=>({n,v}))}];return {class:categories,filters,...await category({id:'comic-drama',page:1})}}
const searchCursors=new Map();
async function search(body){
 const keyword=String(body.wd||'').trim().slice(0,40),pg=Math.max(1,Number(body.page)||1);if(!keyword)return {list:[],page:pg,pagecount:pg,total:0};
 try{
  const previous=pg>1?searchCursors.get(keyword+'|'+(pg-1)):null;
  if(pg>1&&!previous)throw Error('搜索游标过期，请重新搜索');
  const extra={query:keyword,count:'20',offset:String((pg-1)*20),tab_type:'11',bookshelf_search_plan:'4',use_correct:'true',user_is_login:'0',...(previous||{})};
  const result=await api('/reading/bookapi/search/tab/v',null,extra),data=result.data||result;
  const tabs=data.search_tabs||[],tab=tabs.find(t=>Number(t.tab_type)===11)||tabs[0]||{};
  const rows=[],seen=new Set();
  for(const cell of tab.data||[]){const cells=[cell];if(typeof cell.lynx_data==='string')try{cells.push(...(JSON.parse(cell.lynx_data).cell_data||[]))}catch(e){}for(const c of cells){const v=(c.video_data||[]).find(x=>x&&typeof x==='object')||{},id=String(v.series_id||c.book_id||c.search_result_id||''),name=String(c.search_high_light?.title?.text||v.title||v.series_title||c.cell_name||'').trim();if(!/^\d{10,24}$/.test(id)||!name||seen.has(id))continue;seen.add(id);rows.push({vod_id:id,vod_name:name,vod_pic:String(v.cover||v.cover_url||v.series_cover||''),vod_remarks:v.episode_cnt?'全'+v.episode_cnt+'集':''})}}
  if(rows.length){if(searchCursors.size>64)searchCursors.delete(searchCursors.keys().next().value);searchCursors.set(keyword+'|'+pg,{search_id:String(tab.search_id||''),passback:String(tab.passback||tab.next_offset||'')});return {list:rows,page:pg,pagecount:tab.has_more?pg+1:pg,limit:20,total:(pg-1)*20+rows.length+(tab.has_more?1:0)}}
  if(pg>1)return {list:[],page:pg,pagecount:pg,total:0};
 }catch(e){if(pg>1)throw e}
 const data=await page('/search/'+encodeURIComponent(keyword)+'?page=1'),value=data['search_(keyword)/page']||data.search_page||Object.values(data).find(v=>Array.isArray(v?.searchList))||{},seen=new Set(),list=(value.searchList||[]).map(card).filter(v=>{if(!v.vod_id||!v.vod_name||seen.has(v.vod_id))return false;seen.add(v.vod_id);return true});
 return {list,page:1,pagecount:1,limit:list.length,total:list.length};
}
async function detail(body){const id=String(body.id||'');if(!/^\d{10,24}$/.test(id))throw Error('剧集编号无效');const data=await page('/detail?series_id='+id),v=data.detail_page?.seriesDetail||Object.values(data).find(x=>x?.seriesDetail)?.seriesDetail;if(!v)throw Error('官网未返回剧集详情');const vids=(v.vid_list||[]).map(String).filter(x=>/^\d{10,24}$/.test(x));if(!vids.length)throw Error('官网未返回分集');return {list:[{...card(v),vod_id:id,type_name:(v.tags||[]).join(' / '),vod_content:String(v.series_intro||''),vod_remarks:'全'+vids.length+'集',vod_play_from:'自动 · 最高1080P$$$720P$$$480P',vod_play_url:[0,720,480].map(q=>vids.map((vid,i)=>'第'+(i+1)+'集$'+id+':'+vid+'|'+q).join('#')).join('$$$')}]}}
function contentKey(spade){const raw=Buffer.from(spade||'','base64');if(raw.length<3)throw Error('媒体密钥格式无效');const tag=(raw[0]^raw[1]^raw[2])-48,n=raw.length-tag-1;if(tag<1||n<33||n>=raw.length)throw Error('媒体密钥结构无效');const out=Buffer.alloc(n);let even=250,odd=85;for(let i=0;i<n;i++){const cur=raw[i+1],prev=i%2?odd:even;if(i%2)odd=cur;else even=cur;let x=i,count=0;for(;x;x>>>=1)count+=x&1;out[i]=((prev^cur)-21-count)&255}if(!/^[0-9a-fA-F]{32}$/.test(out.subarray(1,33).toString()))throw Error('媒体密钥版本不支持');return Buffer.from(out.subarray(1,33).toString(),'hex')}
function mediaAddress(v){let s=String(v||'').trim();if(!/^https?:\/\//.test(s))s=Buffer.from(s,'base64').toString();if(!/^https?:\/\//.test(s))return '';return s}
async function resolveMedia(vid,quality){
 const result=await api('/novel/player/multi_video_model/v1/',{biz_param:{detail_page_version:0,device_level:3,disable_digg_stat:false,need_all_video_definition:true,need_mp4_align:false,use_os_player:false,use_server_dns:false,video_platform:1024},mixed_video_id_map:{1004:[vid]}});
 const e=result.data?.[vid]||{},model=typeof e.video_model==='string'?JSON.parse(e.video_model):e.video_model;if(!model)throw Error('未返回播放模型');
 let rows=Object.values(model.video_list||{}).map(v=>{const m=v.video_meta||{},enc=v.encrypt_info||{};return {url:mediaAddress(v.main_url)||mediaAddress(v.backup_url),spade:enc.spade_a||'',encrypted:!!enc.encrypt,codec:String(m.codec_type||'').toLowerCase(),quality:parseInt(m.definition)||Math.min(m.vwidth||99999,m.vheight||99999)}}).filter(v=>v.url&&!['bytevc2','bvc2'].includes(v.codec));
 rows.sort((a,b)=>b.quality-a.quality);if(quality)rows=rows.filter(v=>v.quality<=quality);if(!rows.length)throw Error('本集没有兼容的所选画质');const selected=rows[0];if(selected.encrypted&&!selected.spade)throw Error('未返回媒体密钥');return {...selected,key:selected.spade?contentKey(selected.spade):null};
}
async function play(body){const m=String(body.id||'').match(/^(\d{10,24}):(\d{10,24})\|(0|480|720)$/);if(!m)throw Error('分集编号无效');const cacheKey=m[2]+'|'+m[3];let item=mediaCache.get(cacheKey);if(!item||Date.now()-item.created>1200000){const media=await resolveMedia(m[2],Number(m[3]));item={...media,created:Date.now(),id:crypto.randomBytes(12).toString('hex'),ready:false};await prepare(item);if(mediaCache.size>=8)mediaCache.delete(mediaCache.keys().next().value);mediaCache.set(cacheKey,item)}const address=server.address();return {parse:0,url:'http://127.0.0.1:'+address.port+PREFIX+'/video/'+item.id+'.mp4',header:{'User-Agent':'JSTV-Hongguo/1.0'},format:'video/mp4'}}
function boxes(b,start=0,end=b.length){const out=[];for(let p=start;p+8<=end;){let size=b.readUInt32BE(p),head=8;const type=b.toString('ascii',p+4,p+8);if(size===1){if(p+16>end)break;size=Number(b.readBigUInt64BE(p+8));head=16}else if(!size)size=end-p;if(size<head||p+size>end)break;out.push({type,start:p,data:p+head,end:p+size,size});p+=size}return out}
function child(b,box,type){return boxes(b,box.data,box.end).find(x=>x.type===type)}
async function range(url,start,end,signal){const r=await request(url,{headers:{Range:'bytes='+start+'-'+end,Referer:'https://novel.snssdk.com/','User-Agent':APP_UA,'Accept-Encoding':'identity'},timeout:15000,signal,limit:Math.max(end-start+1,512*1024)+1024});if(r.status!==206)throw Error('视频 CDN 未返回分段数据 ('+r.status+')');if(r.data.length!==end-start+1)throw Error('视频 CDN 分段长度异常');return r}
function indexTrack(head,track){const mdia=child(head,track,'mdia'),minf=mdia&&child(head,mdia,'minf'),stbl=minf&&child(head,minf,'stbl');if(!stbl)return [];const sz=child(head,stbl,'stsz'),co=child(head,stbl,'stco')||child(head,stbl,'co64'),sc=child(head,stbl,'stsc'),iz=child(head,stbl,'saiz'),io=child(head,stbl,'saio');if(!sz||!co||!sc||!iz||!io)return [];const count=head.readUInt32BE(sz.data+8),fixed=head.readUInt32BE(sz.data+4),sizes=Array.from({length:count},(_,i)=>fixed||head.readUInt32BE(sz.data+12+i*4));const nco=head.readUInt32BE(co.data+4),offsets=Array.from({length:nco},(_,i)=>co.type==='co64'?Number(head.readBigUInt64BE(co.data+8+i*8)):head.readUInt32BE(co.data+8+i*4)),nsc=head.readUInt32BE(sc.data+4),chunks=Array.from({length:nsc},(_,i)=>({first:head.readUInt32BE(sc.data+8+i*12),samples:head.readUInt32BE(sc.data+12+i*12)}));const flags=head.readUInt32BE(iz.data)&0xffffff,izStart=iz.data+4+(flags&1?8:0),auxDefault=head[izStart],auxCount=head.readUInt32BE(izStart+1);const ioFlags=head.readUInt32BE(io.data)&0xffffff,ioStart=io.data+4+(ioFlags&1?8:0),auxOffset=head[io.data]===1?Number(head.readBigUInt64BE(ioStart+4)):head.readUInt32BE(ioStart+4);if(auxCount!==count)throw Error('MP4 加密采样数量不一致');let sample=0,aux=auxOffset,scIndex=0;const rows=[];for(let ci=0;ci<offsets.length;ci++){while(scIndex+1<chunks.length&&chunks[scIndex+1].first<=ci+1)scIndex++;let pos=offsets[ci];for(let j=0;j<chunks[scIndex].samples&&sample<count;j++,sample++){const auxSize=auxDefault||head[izStart+5+sample];if(auxSize!==8&&auxSize!==16)throw Error('暂不支持此 MP4 子采样加密格式');if(aux+auxSize>head.length)throw Error('MP4 加密索引不在文件头');const iv=Buffer.alloc(16);head.copy(iv,0,aux,aux+auxSize);rows.push({start:pos,end:pos+sizes[sample],iv});pos+=sizes[sample];aux+=auxSize}}if(sample!==count)throw Error('MP4 采样索引不完整');return rows}
function replaceTags(head,from,to){const a=Buffer.from(from),b=Buffer.from(to);for(let p=0;(p=head.indexOf(a,p))>=0;p+=4)b.copy(head,p)}
async function prepare(item){const first=await request(item.url,{headers:{Range:'bytes=0-262143',Referer:'https://novel.snssdk.com/','User-Agent':APP_UA,'Accept-Encoding':'identity'},timeout:15000,limit:512*1024});if(first.status!==206)throw Error('视频 CDN 暂不可用 ('+first.status+')');const total=Number(String(first.headers['content-range']||'').split('/')[1]);if(!total)throw Error('未取得视频长度');let data=first.data;let moov;for(let p=0;p+8<=data.length;){const size=data.readUInt32BE(p),type=data.toString('ascii',p+4,p+8);if(size<8||p+size>8*1024*1024)throw Error('MP4 文件头不兼容');if(type==='moov'){if(p+size>data.length)data=Buffer.concat([data,(await range(item.url,data.length,p+size-1)).data]);moov={start:p,data:p+8,end:p+size};break}p+=size}if(!moov)throw Error('未找到 MP4 视频索引');item.head=Buffer.from(data.subarray(0,moov.end));item.total=total;item.samples=[];if(item.key){for(const trak of boxes(item.head,moov.data,moov.end).filter(x=>x.type==='trak'))item.samples.push(...indexTrack(item.head,trak));if(!item.samples.length)throw Error('未找到加密采样索引');item.samples.sort((a,b)=>a.start-b.start);replaceTags(item.head,'encv',item.codec==='h264'||item.codec==='avc1'?'avc1':'hvc1');replaceTags(item.head,'enca','mp4a');for(let p=0;(p=item.head.indexOf(Buffer.from('sinf'),p))>=0;p+=4)item.head.write('free',p)}item.ready=true;return item}
function transform(item,start,data){const out=Buffer.from(data),end=start+out.length;if(start<item.head.length)item.head.copy(out,0,start,Math.min(end,item.head.length));if(!item.key)return out;let low=0,high=item.samples.length;while(low<high){const mid=(low+high)>>1;if(item.samples[mid].start<=start)low=mid+1;else high=mid}for(let i=Math.max(0,low-1);i<item.samples.length;i++){const sample=item.samples[i];if(sample.start>=end)break;const a=Math.max(start,sample.start),b=Math.min(end,sample.end);if(a>=b)continue;const offset=a-sample.start,blocks=Math.floor(offset/16),skip=offset%16,counter=(BigInt('0x'+sample.iv.toString('hex'))+BigInt(blocks))&((1n<<128n)-1n),iv=Buffer.from(counter.toString(16).padStart(32,'0'),'hex'),dec=crypto.createDecipheriv('aes-128-ctr',item.key,iv);if(skip)dec.update(Buffer.alloc(skip));Buffer.concat([dec.update(out.subarray(a-start,b-start)),dec.final()]).copy(out,a-start)}return out}
async function serveVideo(req,res,id){const item=[...mediaCache.values()].find(x=>x.id===id);if(!item){res.writeHead(410);res.end();return}let start=0,end=item.total-1;const header=req.headers.range;if(header){const m=header.match(/^bytes=(\d*)-(\d*)$/);if(!m){res.writeHead(416,{'Content-Range':'bytes */'+item.total});res.end();return}if(!m[1]){start=Math.max(0,item.total-Number(m[2]));}else {start=Number(m[1]);if(m[2])end=Math.min(end,Number(m[2]));}if(!Number.isSafeInteger(start)||start<0||start>end||start>=item.total){res.writeHead(416,{'Content-Range':'bytes */'+item.total});res.end();return}}const headers={'Content-Type':'video/mp4','Content-Length':end-start+1,'Accept-Ranges':'bytes','Cache-Control':'no-store'};if(header)headers['Content-Range']='bytes '+start+'-'+end+'/'+item.total;res.writeHead(header?206:200,headers);if(req.method==='HEAD'){res.end();return}const controller=new AbortController();res.once('close',()=>controller.abort());try{for(let pos=start;pos<=end&&!res.destroyed;){const last=Math.min(end,pos+512*1024-1);let buf;if(last<item.head.length)buf=item.head.subarray(pos,last+1);else buf=transform(item,pos,(await range(item.url,pos,last,controller.signal)).data);if(!res.write(buf))await new Promise(resolve=>{const done=()=>{res.removeListener('drain',done);res.removeListener('close',done);resolve()};res.once('drain',done);res.once('close',done)});pos=last+1}if(!res.destroyed)res.end()}catch(e){if(!res.destroyed)res.destroy()}}
function send(res,data,status=200){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data))}
function config(){return {video:{sites:[{key:'nodejs_hongguo_local',name:'红果短剧·独立版',type:3,api:PREFIX,searchable:1,quickSearch:1,filterable:1}]},read:{sites:[]},comic:{sites:[]},music:{sites:[]},pan:{sites:[]},color:[]}}
async function handler(req,res){try{const path=new URL(req.url,'http://127.0.0.1').pathname;if(req.method==='OPTIONS'){res.writeHead(204);res.end();return}if(path==='/config'||path==='/full-config')return send(res,config());if(path==='/check')return send(res,{run:true});if(path==='/website'||path==='/website/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end('<!doctype html><meta charset="utf-8"><title>红果短剧独立源</title><h1>红果短剧·独立版</h1><p>1.0.0 · 2026-10-27</p><p>无需账号登录。匿名设备身份与临时播放信息只留在内存中。</p><p>在 JSTV「我的扩展」选择本源即可搜索和观看。</p>');return}const video=path.match(new RegExp('^'+PREFIX+'/video/([a-f0-9]{24})\\.mp4$'));if(video&&['GET','HEAD'].includes(req.method))return await serveVideo(req,res,video[1]);if(req.method!=='POST'||!path.startsWith(PREFIX+'/'))return send(res,{error:'Not Found'},404);const chunks=[];let size=0;for await(const b of req){size+=b.length;if(size>65536)return send(res,{error:'请求过大'},413);chunks.push(b)}const body=parseJSON(Buffer.concat(chunks).toString()||'{}'),action=path.slice(PREFIX.length+1),actions={init:async()=>({}),home,category,search,detail,play};if(!actions[action])return send(res,{error:'Not Found'},404);send(res,await actions[action](body))}catch(e){if(!res.headersSent)send(res,{error:String(e.message||'源请求失败'),message:String(e.message||'源请求失败'),list:[]},502);else res.destroy()}}
async function start(options={}){if(server)await stop();server=typeof globalThis.catServerFactory==='function'?globalThis.catServerFactory(handler):http.createServer(handler);const port=Number(options.port)||9988;await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve)});return server}
async function stop(){if(server){const old=server;server=null;if(typeof old.closeAllConnections==='function')old.closeAllConnections();await new Promise(r=>old.close(r))}agent.destroy();mediaCache.clear();pageCache.clear();searchCursors.clear();identityPromise=null}
module.exports={start,stop,getServer:()=>server};

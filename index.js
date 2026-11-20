/* JSTV 红果短剧独立源 1.0.6, 2026-11-20.
 * SPDX-License-Identifier: GPL-3.0-only
 * PureSign: sunnysky123/hongguo-web, jackotom/hongguo-drama,
 * woshishiq1/drpys. Anonymous registration: qq294716498/HongguoTV-Phone-TV-NoAds.
 * CENC sample indexing adapted from Yswag/xptv-extensions.
 * Media URL decoding adapted from jycao2/hongguoTV (GPL-3.0).
 * Playback v5: sunnysky123/hongguo-web and N3urda/hongguoTV (GPL-3.0-only).
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
 * 红果 App 接口签名，纯 JS 实现（不依赖任何外部进程或 native so）。
 *
 * 算法源自 jackotom/hongguo-drama 的 src/native/app-source.js（GPL-3.0），
 * 其签名与 spade 算法改编自 woshishiq1/drpys，经 N3urda/hongguoTV 传递。
 * 六个签名头按同一算法直接计算，字节级对齐：
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
 * 实现约定：字节统一用 Buffer 并在需要处 `& 0xff` 取无符号；32 位整数溢出
 * 用 `| 0` 对齐；64 位整数运算用 BigInt。
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

/**
 * 读 32 位整型。
 * 入参统一为 Buffer，直接走 Node 内置的 readUInt32LE/BE，
 * 不再手写位移拼接（历史实现是逐字节移位）。
 */
function readLe32(b, off) {
  return b.readInt32LE(off);
}

function readBe32(b, off) {
  return b.readInt32BE(off);
}

/** 写 32 位整型（Buffer 内置，接受 int32 语义）。 */
function putLe32(b, off, v) {
  b.writeInt32LE(v | 0, off);
}

function putBe32(b, off, v) {
  b.writeInt32BE(v | 0, off);
}

function le32(v) {
  const b = Buffer.alloc(4);
  b.writeInt32LE(v | 0, 0);
  return b;
}

function be32(v) {
  const b = Buffer.alloc(4);
  b.writeInt32BE(v | 0, 0);
  return b;
}

/** 读 64 位无符号（Buffer 内置 readBigUInt64LE）。 */
function readU64Le(b, off) {
  return b.readBigUInt64LE(off);
}

function putU64Le(b, off, v) {
  b.writeBigUInt64LE(BigInt.asUintN(64, BigInt(v)), off);
}

/** 64 位循环右移。 */
function rotr64(x, n) {
  const v = BigInt.asUintN(64, x);
  const k = BigInt(n & 63);
  if (k === 0n) return v;
  return BigInt.asUintN(64, (v >> k) | (v << (64n - k)));
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
    head = Buffer.concat([varint((BigInt(tag) << 3n) | 2n), varint(body.length)]);
  } else if (type === 'string') {
    body = Buffer.from(String(value));
    head = Buffer.concat([varint((BigInt(tag) << 3n) | 2n), varint(body.length)]);
  } else if (type === 'float') {
    body = Buffer.alloc(4);
    body.writeFloatLE(Number(value), 0);
    head = varint((BigInt(tag) << 3n) | 5n);
  } else {
    const v = BigInt(Math.trunc(Number(value)));
    head = varint(BigInt(tag) << 3n);
    body = varint(type === 'sint' ? zigzag(v) : v);
  }
  return Buffer.concat([head, body]);
}

/** proto([[tag, value, type], ...]) 的紧凑写法。 */
function proto(fields) {
  const parts = [];
  for (const f of fields) {
    const type = f.length > 2 ? String(f[2]) : 'string';
    parts.push(protoField(Number(f[0]), f[1], type));
  }
  return Buffer.concat(parts);
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
  return Buffer.concat([ret, le32(sumMd5(ret))]);
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
  const input = Buffer.concat([querySm3, bodyMd5, tsBytes, pad,
    Crypto.unhex('a0010000')]);
  const from = ivV0 << 6;
  const to = (ivV0 + 1) << 6;
  const orders = BRANCH2_ORDERS.subarray(from, to);
  return md5SumV3(input, countV2, orders, countV1);
}

/** hashF13 主分支的字表（VendorConstants.hashTable，v3 与 v5 共用）。 */
const HASH_TABLE = [
  0xebb64faf, 0x07aadcc2, 0xcf3187bf, 0xe01138ff, 0x6d0bfcff, 0x5a30a3be, 0xb41ad638, 0x34180eb8,
  0xf233eb6f, 0xb1a584cc, 0xccc30dc7, 0x47d1db51, 0xd55653de, 0x70a84fa1, 0x57473c12, 0xf76f0288,
  0x2c077f0a, 0xda0dcad0, 0xfbb86f6c, 0xfdc4cf00, 0x688a020d, 0xe676c6a6, 0x8cd6338b, 0x1a3c8d0e,
  0xcce8b06b, 0x6ad0ed0b, 0xa0522717, 0xdc71ac83, 0x2285db71, 0xd5b4dda6, 0x736f8650, 0x6560306c,
  0x617ce2a6, 0xe423417e, 0x0a40e143, 0x544e4032, 0x88dffb2a, 0x716c1ae0, 0x4c467a88, 0x05b23bb3,
  0xe1d0b866, 0xbaa3dcb8, 0xae3374d3, 0xc3381a50, 0x1702f75b, 0xfe6da368, 0xf0b4cf48, 0x4e0ffbb8,
  0x72aad10d, 0x26c53a3d, 0xf2bce0f6, 0xb4557581, 0x4a257fdd, 0x8c3182a2, 0xab0b3b86, 0x3d5dfb14,
  0x4f103634, 0xd37b52d7, 0x444eff16, 0xeb0a33d1, 0x6ca86f6e, 0x0284ba7, 0x08387cfa, 0x5fb37586];

/** hashF13：按 iv 低 4 位选分支（0 为主分支，1 不被服务端接受，2 为备用变体）。 */
function hashF13(querySm3, bodyMd5, tsBytes, khronos) {
  const iv = getIv(getIv(getIv(0x20230928, querySm3), bodyMd5), tsBytes);
  const low = iv & 15;
  const ivV0 = (low * 171) >> 9;
  const branch = low - ivV0 * 3;
  if (branch === 2) return branch2F13(iv, querySm3, bodyMd5, tsBytes, khronos);
  if (branch !== 0) {
    return Buffer.concat([querySm3.subarray(0, 16), bodyMd5,
      le32(sumMd5(Buffer.concat([querySm3, bodyMd5])))]);
  }

  const ivV1List = [0xc4a78580, 0xb3c0fd39, 0xc58c5686, 0xc9aa3ba7, 0xf5a7adf2, 0x963c2ed1];
  const ivV1 = ivV1List[ivV0] | 0;
  const countV1 = (ivV1 + khronos + 1) & 255;
  const countV2 = (ivV1 + khronos) | 0;
  const tt = new Array(HASH_TABLE.length);
  for (let i = 0; i < tt.length; i++) tt[i] = ror(HASH_TABLE[i], countV1);
  const n0 = (countV2 + 2) & 7;
  const seed = [0xfa, 0x45, 0x61, 0xd7];
  // JS: Buffer.from(seed.map(...)) —— seed 仅 4 个元素，pad 为 4 字节
  const pad = Buffer.alloc(seed.length);
  for (let i = 0; i < seed.length; i++) pad[i] = ((seed[i] | (seed[i] << 8)) >> n0) & 255;
  const data = Buffer.concat([querySm3, bodyMd5, tsBytes, pad,
    Crypto.unhex('00000000000001a0')]);

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
  return Buffer.concat([ret.subarray(0, 16), le32(sumMd5(ret.subarray(0, 16)))]);
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
  const q4 = md5(Buffer.from(query)).subarray(0, 4);
  const b4 = body != null && body.length > 0
    ? md5(body).subarray(0, 4) : Buffer.alloc(4);
  const sdk = le32(67503104);
  const input = Buffer.concat([q4, b4, Buffer.alloc(4), sdk, be32(timestamp | 0)]);
  const key = [0x4a, 0x40, 0x16, (random >> 8) & 255, 0x47, 0x6c, 0x01, random & 255];
  const out = rc4Gorgon(input, key);
  for (let i = 0; i < out.length; i++) {
    const value = rotl8(out[i] & 0xff);
    const next = i + 1 < out.length ? (out[i + 1] & 0xff) : (out[0] & 0xff);
    out[i] = (~(reverseBits((next ^ value) & 255) ^ 20)) & 255;
  }
  return Crypto.hex(Buffer.concat([Crypto.unhex('8404'),
    Buffer.from([random & 255, (random >> 8) & 255, 0x40, 0x01]), out]));
}

// ==================== AesV3（medusa 内置的 AES 变体） ====================

const SBOX_V3 = Buffer.from(
  '+n0Ia5xZs0sEXznQOEqRmQBnpiCf9U2Ccybu3xhmgzOAAxn72f6uqqmwUsYL83klTni0NqxdGieeiNu9PGPsSRXBMB/cuFbUbM3KCUPINaPvHvSW0vwOcnuUhNHqRVpiAj/TEoE0K91+5ijypUYTATsh9mE3KSoN7Yyvv51cuyR2D3XkU4nhmI2xmmVwT1RMWKtub4sjxAcRDLrPoKSO2AU9FLLadMPX577Wf95IFj6FkKFVt3dCIsmGUC4X+WQxLJvxbRxEaOPpqJOXyzJX6+Vxaq3AzMfF/WAdoi1Hp+JRaV56zgpBtpWP97mH4DoGEIq1+FvV8LyS/3wvwugbQOwb2r26mJEMsiuDQTRn+wrYdrVGBVlhI3WQhyrjUBVMrLF5667llUcEaPCGPVGLD8qO5LlO8hKCvA7V9+8oJc9bXelqVQLhM76T5/WtnT45JKji+hdX0HoNCDDWuKON/QeaxB5uImSX0h2wv0VmP2zd2yeApxHcpsVS+MC2yFwAc2B7oBkTqsk1SEvTpM2fmfMQREBUfin0Bh+iq6EvPPavhWI2IX9e3yAas7Tm/3KEj2UmlFp36kN4x0rMLBRrxuh0U/zUHM4xcAMYjJY4MonxOl/X+alpt2M3WMI7w3HLnpIBigtNiJu7T21v4P6lSd5WFgntnMEt7oF92XzRLkJbTcGmXepE/UVOG6E/0YnhfS+q26utWcuxzpooyeD2cDlK1/8w9d28VzsRjbLuALbmGlp8+d7EzS6Au7lMpZ+ECMZvQmzwJ+eLOpxR+2chdUExp8ogQyq3v9l68rX4jCwjg0+PYKAEEzcU4wHFY2ZcdIHfWL1okD3SszT0GZMyKdZJrg1L2AeerB4tC0C4crp2EHGo5FYdSP7lwkeR2ocmnR+Ia8CYviUJlzOjhRZef9xuVOn3qcjow3fQgivsAmKKkg4+sA8F8/GWeDiGNhg8JM8KtFPMYWWkx5TVFX5t73kiNRJqjlIGVXtGZFCV4gzt0xcDopuZ6xz8r9Rzafpf9ywev8jh8592gHFIqpStZPuJxmDDMrNN0uBE3V+oscdoIzTJbRJ/t+sVvqnReJOgDJKk10fjisJwqyZBmnmn2BSFj8BvVtCMEbkuPOKdzw7eA11GPs04Qw8zWtkaZWwiO/wwpojqN6K0jY5RnNZA7vn4hPSul+nKCkVnVwQvg1zVxcSCtqORmB9KrJaBbssbCQivGJVJfVTt+hYxOtq4ZvWl8f4QAQZ0zGPffCgl9s6yT4vlvIdpu4YhBwA25wtQWZsc6GJYGWHyvSdeuh3mmUI9DSq13Fsp8C1MU3tqc04/df9LoTUXVXI5INOw/e8C7Hd+5CvbkMEFnnrUUmskEw==',
  'base64');

// ==================== v5 播放签名常量（Android v04.10.03 Medusa/Helios/Khronos） ====================
// 来源：N3urda/hongguoTV V5Constants（GPL-3.0-only）。协议常量，非账号凭据。

/** v5 medusa 的 magic16（消息 field 1 与最终前缀）。 */
const V5_MAGIC = Crypto.unhex('2d4b4fca49750d433fb5ae2c226dcc56');

/** v5 helios / medusa 的版权方标识。 */
const V5_LICENSE = '646637794';

/** v5 medusa 的签名密钥（32 字节）。 */
const V5_SIGN_KEY = Crypto.unhex(
  'b23c2a470a20d105dc3f8c4438f8272ed46d6c89ffdcdedd5108698d26e9489d');

/** v5 AesV3 的 4 段 S 盒（每段 256 字节）。 */
const V5_SBOX = Crypto.unhex(
  '53290fe9e51f316f90f74a7e034d367784ab49237cd0135cdc632c322fd3be0e'
  + '2624a417ecd9151a7ff64f60730a87f9445ec6ada2f865d22b696c4188f24c0d'
  + 'f37b75510b939f6bc2fe6883e68bc8c722181ba0bdb08c9871b50c9a16b46ee'
  + 'a8eed20ba4b8a14e0fcf1468dbbef05a93e5a9d7dcf06898635c1fd99f5de287a'
  + '80c594daaab19b6279fbd75070cb52eb2555c456e39e7839853874e2f0013ac0'
  + 'b64742d8ca10e4b79c955de8b843ce4ed464a6a72ed508091c92e7b3eedd1e1d'
  + 'd12afac321618fa3d65f9167c982f43d66a53c6a1997585b346dbf9672ff37cd'
  + 'bc073b2dae11453304df00815476b2a13fccdb30b957a8acafe1274002485912'
  + '38922563e36406d37a24100b7902a028044e218453c2a399199c9d13dc40c55b'
  + 'a67e502273850ebdc1a2e2188b8f2d9e3cb909b8c46a2a9f4a6dd93007eafa65'
  + 'b7b3a881aa908cc74f0ad76bbbb58617c37012ca05a469fd44e62eecf1e4272c'
  + 'e860c0ae5eadf99b20d8f0234174006f3f110d7657d01645d4eff8f71471cbfe'
  + '1cb2f52648727bf3c9de55153e031b4d61757db63dbf7782eeafe9018a889136'
  + '2fb14759ac32bab03b349aeb5a377c5156be4c8dfbe13a684bda39cf836697c8'
  + '94545fe0f2491acea9fc6252f4ff1e0fe72bd2df6e67a7f635e5bcc6d1a5dd95'
  + '1d89960887a18eb40c785cdb1f80ed42299333ab98cdd67f316cd54346585dcc'
  + 'd759fb722789b08807cc0fda293f7e5e1819bb0353517020b31d3d00374952be'
  + 'a2c421e862040a9ec892a05b266b7a0d0cc316f483b81af39715657ffe32ad8d'
  + 'e0c13077646035236ee5363e5f900e9a7cf850a81cd9960b6df73317226f99ea'
  + 'a6fff15cec34acb98246639b918ab2851466a7cdfc4ad1b52c2ae95a58d3734e'
  + '47ddd5b7560193f644ef9c408b7dee39b4d6aabf4de761e3252d4c7ba3843187'
  + '745d55e6a5db05d42b45caed43c0c5d0b64bfa9d94a4a9d8f2f0e1a108dcfd28'
  + '8fd2bc1fc7bd675412138169cb09249875ba3b68cfb11180afae104fc9789571'
  + 'c6dfce02413886796ae21e3c488cc21b9f423a066c2eabf98e2fdeeb5776e4f5'
  + 'd09a515ba58cbbab3e37b09fd4f6d9244df80512e84cd7956be301cf64f1429d'
  + '58577cc241f3a2c655144f81aaf95a4e108da894b38970561ae9002619fbbac9'
  + '1fa922ed202bfc62cb08e0de2a7f3631435f8b47c8a3c563b4db4071ce74c46d'
  + 'a6fa696a9e282d1e825d663b93bfd56c48dce1884bb10fccea063929f746443f'
  + 'd830a4232e53da21a1f2d1bdfebc3a02c10a1b8ad31d04fd616590d272ac737e'
  + '98eb33af60528716bee78ec0ee8699031177277d9cff32542c67caf5f4459168'
  + '1335ae0e178f3409a7803db83892dde5b9b7f0c750e24aef077badd678a09b85'
  + '0b84ec1597e4963cb5e675df1c0d6fb618496ecd76c35c798325590c2fb27a5e');

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
  constructor(key, khronos, v5) {
    const isV5 = v5 === true;
    this.wordSize = khronos & 3;
    this.box = (isV5 ? V5_SBOX : SBOX_V3)
      .subarray(this.wordSize * 256, (this.wordSize + 1) * 256);
    const con2Table = isV5
      ? [[2, 0, 3, 1], [1, 3, 2, 0], [3, 2, 1, 0], [2, 3, 1, 0]]
      : [[1, 0, 2, 3], [2, 0, 3, 1], [0, 1, 3, 2], [1, 0, 2, 3]];
    const orderTable = isV5
      ? [
        [0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11],
        [0, 9, 14, 11, 4, 13, 2, 3, 8, 1, 6, 15, 12, 5, 10, 7],
        [0, 9, 14, 3, 4, 13, 2, 15, 8, 1, 6, 11, 12, 5, 10, 7],
        [0, 9, 14, 15, 4, 13, 2, 3, 8, 1, 6, 11, 12, 5, 10, 7]]
      : [
        [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3],
        [0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11],
        [0, 9, 14, 7, 4, 13, 2, 11, 8, 1, 6, 3, 12, 5, 10, 15],
        [0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3]];
    this.con2 = con2Table[this.wordSize];
    this.order = orderTable[this.wordSize];
    // wire/compact：明文 32 字节与源数据 248 字节之间的位抽吸映射（v5 与 v3 不同）。
    this.wire = isV5 ? [6, 5, 3, 4, 2, 7, 1, 0] : [5, 6, 2, 4, 3, 1, 0, 7];
    this.compact = isV5 ? [1, 7, 3, 6, 2, 0, 4, 5] : [1, 6, 0, 7, 2, 4, 5, 3];
    const init = (isV5
      ? [0xbbb5de72, 0xd4638d5b, 0x92a5f73b, 0x89f8a1c9]
      : [0xca025ddc, 0x823dc546, 0xc9420583, 0xc298225f])[this.wordSize];
    const initial = Buffer.alloc(16);
    for (let i = 0; i < 4; i++) putLe32(initial, i * 4, init);
    const mk = xorBytes(initial, key);
    const expanded = Buffer.concat([mk, Buffer.alloc(32)]);
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
    const wire = this.wire;
    const compact = this.compact;
    const plaintext = Buffer.alloc(32);
    for (let i = 0; i < 31; i++) {
      const at = i * 8;
      let acc = 0;
      for (let j = 0; j < 8; j++) {
        acc |= (((aesSrc(data, at + j) >>> wire[j]) & 1) << compact[j]);
      }
      plaintext[i] = acc & 0xff;
    }
    plaintext[31] = 1;
    const blocks = [];
    let previous = Buffer.from(iv);
    for (let i = 0; i < plaintext.length; i += 16) {
      const value = this.block(xorBytes(plaintext.subarray(i, i + 16), previous));
      blocks.push(value);
      previous = value;
    }
    const key = Buffer.concat(blocks);
    const out = Buffer.from(data);
    for (let i = 0; i < 31; i++) {
      const at = i * 8;
      const k = key[i] & 0xff;
      // JS 语义：越界读写均静默忽略，故读用 aesSrc()、写用 aesPut()
      for (let j = 0; j < 8; j++) {
        const bit = wire[j];
        const mask = ((1 << bit) & 0xff);
        aesPut(out, at + j,
          (aesSrc(out, at + j) & ((~mask) & 0xff))
          | (((k >>> compact[j]) & 1) << bit));
      }
    }
    return Buffer.concat([key.subarray(key.length - 1, key.length), out]);
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
  const hash = sm3(Buffer.concat([signKey, le32(random), signKey]));
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

/** 返回 [0, n) 的随机整数。 */
function rndInt(n) {
  return crypto.randomInt(n);
}

/**
 * 返回无符号 32 位随机整数（0 ~ 2^32-1）。
 *
 * 参考实现的随机源是 `Math.floor(Math.random() * 0x100000000)`，恒为非负；
 * 这里同样取无符号，避免下游对符号做隐式假设（medusa 的 `random >> 16`、
 * `le32(random)` 都基于「非负 32 位整数」这一前提）。
 */
function rndInt32() {
  return crypto.randomBytes(4).readUInt32BE(0);
}
function legacyRandomInt32() {
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
  const querySm3 = sm3(Buffer.from(query));
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
  const queryHash = sm3(Buffer.concat([Buffer.from(query), bodyMd5,
    Buffer.from('none')]));

  const nested = proto([
    [1, 111, 'sint'], [2, 10, 'sint'], [3, 694367, 'sint'], [5, 586952199, 'sint']]);
  const message = proto([
    [1, MEDUSA_MAGIC16, 'bytes'], [2, 3, 'sint'], [3, messageRandU, 'sint'],
    [4, '8662'], [5, deviceId], [6, '1588093228'], [7, version],
    [8, 'v04.06.04-ml-android'], [9, 67503104, 'sint'],
    [10, MEDUSA_MAGIC8, 'bytes'], [12, khronos, 'sint'],
    [13, queryBodyTs, 'bytes'], [14, querySm3.subarray(0, 6), 'bytes'],
    [15, nested, 'message'], [16, PROCESS_NONCE], [17, khronos, 'sint'],
    [19, queryHash, 'bytes'], [20, 'none'], [21, 312, 'sint'],
    [23, env, 'message'],
    [24, '{"cmr":16777216,"cmr2":16777216,"un_h":1879194040,"vpn":0,'
    + '"kd":0,"fkd":3672518972,"pd":-1872573247,"dyn":"",'
    + '"do":0,"tk":true}']]);

  const random = legacyRandomInt32();
  const hs = keyHash(MEDUSA_SIGN_KEY, random);
  const hash = hs[0];
  const seed = hs[1];
  let transformed = xmxor(message, hash);
  transformed = Buffer.concat([MEDUSA_MAGIC8, transformed]);
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
  const xmRand = legacyRandomInt32();
  const packed = Buffer.concat([Buffer.from([0x35]), le32(xmRand), le32(check), transformed,
    Buffer.from([(random >> 16) & 255, (random >> 24) & 255])]);
  const encrypted = new AesV3(MEDUSA_AES_KEY, khronos).encrypt(packed, MEDUSA_AES_IV);
  const versionBytes = Crypto.unhex('03000000f7e85ffad7d7dc3bd62ac87057cf6118');
  const prefix = Buffer.alloc(20);
  for (let i = 0; i < 20; i += 4) {
    // JS: u32(version.readUInt32LE(i) ^ khronos) 后 writeUInt32LE
    putLe32(prefix, i, (readLe32(versionBytes, i) ^ (khronos | 0)));
  }
  return Buffer.concat([prefix,
    Buffer.from([random & 255, (random >> 8) & 255, 0, 1]), encrypted]).toString('base64');
}

/** helios：md5 ASCII 化 -> 64 位字表 -> 34 轮扩展 -> 分组类 Feistel。 */
function helios(khronos) {
  return heliosWith(khronos, rndInt32());
}

/** v5 helios：与 v3 同算法，仅 license 换成 646637794（N3urda/hongguoTV V5）。 */
function heliosV5(khronos) {
  return heliosWith(khronos, rndInt32(), V5_LICENSE);
}

/** 可注入 random 与 license 的 helios（默认 license 为 v3 的 1588093228）。 */
function heliosWith(khronos, random, license) {
  const digest = md5(Buffer.concat([le32(random), Buffer.from('8662')]));
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
  const text = String(khronos) + '-' + (license || '1588093228') + '-8662';
  const tb = Buffer.from(text);
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
  return Buffer.concat(all).toString('base64');
}

// ==================== v5 播放签名（Android v04.10.03 Medusa/Helios/Khronos） ====================

/**
 * v5 hashF13：iv 低 4 位固定等于 12（branch 0），ivV1 / chosen 为 v5 常量。
 * 与 v3 主分支共用同一套 di 展开 / 主循环，仅参数与末尾校验位（|0x20）不同。
 */
function hashF13v5(querySm3, bodyMd5, tsBytes, khronos) {
  const ivV1 = 0x9d4a97c2 | 0;
  const countV1 = (ivV1 + khronos + 1) & 255;
  const countV2 = (ivV1 + khronos) | 0;
  const tt = new Array(HASH_TABLE.length);
  for (let i = 0; i < tt.length; i++) tt[i] = ror(HASH_TABLE[i], countV1);
  const n0 = (countV2 + 2) & 7;
  const seed = [0xfa, 0x45, 0x61, 0xd7];
  const pad = Buffer.alloc(seed.length);
  for (let i = 0; i < seed.length; i++) pad[i] = ((seed[i] | (seed[i] << 8)) >> n0) & 255;
  const data = Buffer.concat([querySm3, bodyMd5, tsBytes, pad,
    Crypto.unhex('00000000000001a0')]);

  const di = new Array((data.length / 4) + 112 + 16).fill(0);
  let diLen = 0;
  for (let i = 0; i + 3 < data.length; i += 4) di[diLen++] = readBe32(data, i);
  let di0 = di[0];
  for (let i = 0; i < 112; i++) {
    const di1 = di[i + 1];
    const di14 = di[i + 14];
    const r1 = rotl(di1, 14) ^ rotl(di1, 25) ^ (di1 >>> 3);
    const r2 = rotl(di14, 13) ^ rotl(di14, 15) ^ (di14 >>> 10);
    di[diLen++] = (di0 + di[i + 9] + r1 + r2) | 0;
    di0 = di1;
  }

  const initRaw = [0x7aba4fc8, 0x67166507, 0x6403fa00, 0x340f512f,
    984304912, 3005047866, 2874125293, 2152413264];
  const init = new Array(8);
  for (let i = 0; i < 8; i++) init[i] = ror(initRaw[i], countV2 & 31);
  const chosen = [96, 1, 3, 4, 0, 6, 5, 2, 0, 7, 7];
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
    const last = d[d.length - 1];
    for (let k = d.length - 1; k >= 1; k--) d[k] = d[k - 1];
    d[0] = last;
    d[chosen[10]] = (n7 + n4) | 0;
    d[chosen[8]] = (old + n4) | 0;
  }
  const ret = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) putBe32(ret, i * 4, (d[i] + init[i]) | 0);
  for (let i = 0; i < 16; i++) ret[i] = ret[i] ^ ret[i + 16];
  return Buffer.concat([ret.subarray(0, 16),
    le32((sumMd5(ret.subarray(0, 16)) | 0x20) | 0)]);
}

/**
 * v5 x-medusa。移植自 N3urda/hongguoTV Signer.medusaV5（GPL-3.0-only）。
 *
 * @param {string} url 完整 URL（含 query，签名按 '?' 之后的原文计算）
 * @param {Buffer|null} body 实际发送的 gzip 压缩体
 * @param {number} khronos 秒级时间戳
 * @param {object} who { device_id, version_name, channel, device_type, os_version }
 */
function medusaV5(url, body, khronos, who) {
  const bodyMd5 = body != null && body.length > 0 ? md5(body) : Buffer.alloc(16);
  const query = queryOf(url);
  const querySm3 = sm3(Buffer.from(query));
  const ts = le32(khronos | 0);
  const f13 = hashF13v5(querySm3, bodyMd5, ts, khronos);

  const version = who.version_name;
  const deviceInfo = proto([
    [1, 1, 'sint'], [2, 2, 'sint'], [3, '8662'], [4, who.device_id],
    [5, PROCESS_NONCE], [6, '!noperm!'], [12, 'Asia/Shanghai,8'], [13, 'zh_CN'],
    [22, who.os_version], [25, PROCESS_STARTED, 'sint'],
    [30, who.device_type], [31, 'HONOR'], [32, who.device_type], [34, 'HONOR']]);
  const env = proto([
    [6, 'v04.10.03.04-bugfix'], [8, who.channel],
    [12, deviceInfo, 'message'], [14, version]]);
  const message = proto([
    [1, V5_MAGIC, 'bytes'], [2, 5, 'sint'], [3, rndInt32(), 'sint'],
    [4, '8662'], [5, who.device_id], [6, V5_LICENSE],
    [7, version], [8, 'v04.10.03-ml-android'], [9, 0x040a0300, 'sint'],
    [10, Buffer.alloc(8), 'bytes'], [12, khronos, 'sint'], [13, f13, 'bytes'],
    [14, querySm3.subarray(0, 6), 'bytes'],
    [15, proto([[1, 1, 'sint'], [2, 1, 'sint'], [3, 1, 'sint'], [5, 1, 'sint']]), 'message'],
    [17, khronos, 'sint'], [20, 'none'], [21, 377, 'sint'], [23, env, 'message'],
    [24, '{"cmr":16777216,"cmr2":16777216,"un_h":11,"vpn":0,"kd":0,"dyn":"","do":1,"tk":true}']]);

  const nonce = rndInt32();
  const hs = keyHash(V5_SIGN_KEY, nonce);
  const hash = hs[0];
  const seed = hs[1];
  // transformed = (flags(8 零字节) + xmxor(message, hash)) 整体逆序，再逐字节异或 seed[~i & 3]
  let transformed = xmxor(message, hash);
  transformed = Buffer.concat([Buffer.alloc(8), transformed]);
  for (let i = 0, j = transformed.length - 1; i < j; i++, j--) {
    const t = transformed[i];
    transformed[i] = transformed[j];
    transformed[j] = t;
  }
  for (let i = 0; i < transformed.length; i++) {
    transformed[i] = (transformed[i] ^ seed[(~i) & 3]) & 0xff;
  }
  const check = (((querySm3[0] & 63) << 14) | 0x18000001 | ((f13[0] & 63) << 8)) | 0;
  const xmRand = rndInt32();
  const packed = Buffer.concat([Buffer.from([0xca]), le32(xmRand), le32(check), transformed,
    Buffer.from([(nonce >>> 16) & 255, (nonce >>> 24) & 255])]);
  const encrypted = new AesV3(md5(V5_SIGN_KEY.subarray(0, 16)), khronos, true)
    .encrypt(packed, md5(V5_SIGN_KEY.subarray(16, 32)));
  const prefix = Buffer.concat([le32(5), V5_MAGIC]);
  const tsLE = le32(khronos | 0);
  for (let i = 0; i < prefix.length; i++) {
    prefix[i] = (prefix[i] ^ tsLE[i & 3]) & 0xff;
  }
  return Buffer.concat([prefix,
    Buffer.from([nonce & 255, (nonce >>> 8) & 255, 0, 1]), encrypted]).toString('base64');
}

/** v5 分支：iv 低 4 位等于 12 才算 branch 0（与 signPlayback 的选 ticket 逻辑一致）。 */
function branchV5(queryStr, body, khronos) {
  const bodyMd5 = body != null && body.length > 0 ? md5(body) : Buffer.alloc(16);
  const q = sm3(Buffer.from(queryStr));
  const iv = getIv(getIv(getIv(0x20230928, q), bodyMd5), le32(khronos | 0));
  return ((iv & 15) === 12) ? 0 : 1;
}

/** v5 query 编码：与参考实现的 URLEncoder 兜底一致（只额外转 !'()）。 */
function signV5Encode(value) {
  return encodeURIComponent(String(value))
    .replace(/[!'()]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function encodeV5Query(values) {
  const parts = [];
  for (const k of Object.keys(values)) {
    parts.push(signV5Encode(k) + '=' + signV5Encode(String(values[k])));
  }
  return parts.join('&');
}

/**
 * v5 播放签名：在 0..1023 内调整 _rticket 直到 branch 0，返回最终 URL 与签名头。
 * 对应 N3urda/hongguoTV Signer.signPlayback（mobileV5=true）。
 *
 * @param {string} base 不含 query 的接口 URL
 * @param {object} values 有序 query 参数（不含 _rticket，本函数内部追加并抖动）
 * @param {Buffer|null} body gzip 压缩体
 * @param {number} now 毫秒时间戳
 * @returns {{url: string, headers: object}}
 */
function signPlaybackV5(base, values, body, now) {
  const ts = Math.floor(now / 1000);
  for (let offset = 0; offset <= 1023; offset++) {
    const ticket = now + offset;
    const query = encodeV5Query(Object.assign({}, values, { _rticket: String(ticket) }));
    if (branchV5(query, body, ts) !== 0) continue;
    const url = base + '?' + query;
    const headers = {
      'x-khronos': String(ts),
      'x-helios': heliosV5(ts),
      'x-medusa': medusaV5(url, body, ts, values),
    };
    if (body != null && body.length > 0) {
      headers['Content-Type'] = 'application/json; charset=utf-8';
      headers['x-ss-stub'] = md5(body).toString('hex').toUpperCase();
    }
    return { url, headers };
  }
  throw new Error('无法生成播放签名');
}

// ==================== 分支判定与入口 ====================

/** 与 hashF13 相同的分支计算；branch==1 时服务端不认，调用方应抖动 _rticket 避开。 */
function branchOf(url, body, khronos) {
  const bodyMd5 = body != null && body.length > 0 ? md5(body) : Buffer.alloc(16);
  const q = sm3(Buffer.from(queryOf(url)));
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
  out['x-ladon'] = be32(ts | 0).toString('base64');
  out['x-argus'] = le32(ts | 0).toString('base64');
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

/**
 * 仅供自检：用 query/body 明文跑一次 hashF13，返回十六进制。
 *
 * hashF13 有三个分支（0/1/2），分支 0 的展开循环里有一处「上一轮值」的
 * 状态推进，最容易被改错；给三个分支各留一组固定向量，退化时自检立刻报错。
 */
function hashF13Hex(queryText, bodyText, khronos) {
  return hashF13(sm3(Buffer.from(queryText)), md5(Buffer.from(bodyText)),
    le32(khronos), khronos).toString('hex');
}

module.exports = {sign,branchOf,signPlaybackV5};

return module.exports;})();

const REG_CONSTANTS=Buffer.from([77,212,194,230,184,49,98,9,14,82,179,199,166,115,59,164,28,178,70,43,130,154,181,138,25,107,57,219,87,23,117,36,244,155,175,127,8,232,214,141,38,167,46,55,193,169,90,47,31,5,165,24,146,174,242,148,151,50,182,42,56,170,221,88]);
async function registerAnonymous(signal){
 const now=Date.now(),cdid=crypto.randomUUID();
 const header = {
   display_name: '红果免费短剧', update_version_code: 73932, manifest_version_code: 73932,
   app_version_minor: '7.3.9.32', aid: 8662, channel: 'update_64', package: 'com.phoenix.read',
   app_version: '7.3.9.32', version_code: 73932, sdk_version: '3.7.0-rc.34-fanqie-xiaoshuo',
   sdk_target_version: 29, git_hash: '3a88f4e', os: 'Android', os_version: '16', os_api: 36,
   device_model: '25053RT47C', device_brand: 'Redmi', device_manufacturer: 'Redmi',
   cpu_abi: 'arm64-v8a', release_build: 'b5e187f', density_dpi: 520, display_density: 'mdpi',
   resolution: '1280x2772', language: 'zh', timezone: 8, access: 'wifi', not_request_sender: 0,
   carrier: 'CHINA MOBILE', mcc_mnc: '46000', rom: 'eng.root.20231116.160340',
   rom_version: 'W528JS release-keys', cdid,
   sig_hash: '56a962410c494bbaf0b58dba20cae56f', openudid: crypto.randomBytes(8).toString('hex'),
   clientudid: crypto.randomUUID(), ipv6_list: [], region: 'CN', tz_name: 'Asia/Shanghai',
   tz_offset: 28800, sim_region: 'cn', sim_serial_number: [], oaid_may_support: false,
   req_id: crypto.randomUUID(), device_platform: 'android',
   custom: { account_region_src: 'fallback', account_region: 'cn', host_bit: 64,
     dragon_device_type: 'phone' },
   pre_installed_channel: '',
   apk_first_install_time: now, is_system_app: 0, sdk_flavor: 'china', guest_mode: 0,
 };
 const raw=Buffer.from(JSON.stringify({magic_tag:'ss_app_log',header,_gen_time:now})),gz=zlib.gzipSync(raw),seed=crypto.randomBytes(32),sha=x=>crypto.createHash('sha512').update(x).digest(),km=sha(Buffer.concat([sha(seed),REG_CONSTANTS])),plain=Buffer.concat([sha(gz),gz]),cipher=crypto.createCipheriv('aes-128-cbc',km.subarray(0,16),km.subarray(16,32)),body=Buffer.concat([Buffer.from([0x74,0x63,0x05,0x10,0,0]),seed,cipher.update(plain),cipher.final()]);
 const url='https://log5-applog-lf.fqnovel.com/service/2/device_register/?tt_data=a&cronet_version=8d40f833_2026-03-03&ttnet_version=4.2.243.31-douyin&use_store_region_cookie=1';
 const r=await request(url,{method:'POST',body,headers:{'Content-Type':'application/octet-stream;tt-data=a','Log-Encode-Type':'gzip','X-SS-DP':'8662','X-SS-Req-Ticket':String(now),'X-Vc-Bdturing-Sdk-Version':'4.0.3.cn','Lc':'101','Sdk-Version':'2','Passport-Sdk-Version':'5051452','X-Neptune':'-8|50:51:59:30:40:47:49:39','X-SS-STUB':crypto.createHash('md5').update(body).digest('hex').toUpperCase(),'User-Agent':'com.phoenix.read/72232 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3)'},timeout:8000,followRedirect:false,signal});
 checkPlaybackResponse(r,'匿名设备接口');
 const text=r.data.toString();if(!text)throw Error('匿名设备接口未返回内容');
 const x=JSON.parse(text.replace(/("(?:device_id|install_id)"\s*:\s*)(\d{16,})/g,'$1"$2"'));
 checkPlaybackCode(x,'匿名设备接口');
 const did=String(x.device_id_str||x.device_id||''),iid=String(x.install_id_str||x.install_id||'');
 if(!/^\d{10,24}$/.test(did)||!/^\d{10,24}$/.test(iid)||!Number(did)||!Number(iid))throw Error('匿名设备接口未返回有效身份');
 return {device_id:did,install_id:iid,cdid};
}


const BASE='https://hongguoduanju.com',PREFIX='/spider/hongguo_local/3';
const WEB_UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36';
const APP_UA='com.phoenix.read/73532 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3)';
const agent=new https.Agent({keepAlive:true,maxSockets:8});
let server,identityPromise=null;
const pageCache=new Map(),mediaCache=new Map(),pendingMedia=new Map();
let playbackLifetime,playbackQueue=Promise.resolve(),nextPlaybackAt=0,playbackRetryAt=0;
function request(url,opts={},redirects=0){
 return new Promise((resolve,reject)=>{
  const u=new URL(url);if(!['https:','http:'].includes(u.protocol))return reject(Error('不支持的地址协议'));
  const mod=u.protocol==='https:'?https:http;
  const req=mod.request(u,{method:opts.method||'GET',agent:u.protocol==='https:'?agent:undefined,headers:{'User-Agent':WEB_UA,'Accept-Encoding':'gzip, deflate, br',...opts.headers}},res=>{
   if(opts.followRedirect!==false&&[301,302,303,307,308].includes(res.statusCode)&&res.headers.location){res.resume();if(redirects>=3)return reject(Error('跳转过多'));return request(new URL(res.headers.location,u).href,opts,redirects+1).then(resolve,reject)}
   const chunks=[];let size=0,limit=opts.limit||12*1024*1024;
   res.on('data',c=>{size+=c.length;if(size>limit){req.destroy(Error('响应超出限制'));return}chunks.push(c)});
   res.on('error',reject);res.on('end',()=>{try{let data=Buffer.concat(chunks);const enc=data.length&&res.headers['content-encoding'];if(enc==='gzip')data=zlib.gunzipSync(data);else if(enc==='br')data=zlib.brotliDecompressSync(data);else if(enc==='deflate')data=zlib.inflateSync(data);if(data.length>limit)return reject(Error('响应超出限制'));resolve({status:res.statusCode,headers:res.headers,data})}catch(e){reject(Error('响应解码失败'))}});
  });
  req.setTimeout(opts.timeout||15000,()=>req.destroy(Error('上游请求超时')));req.on('error',reject);
  if(opts.signal){if(opts.signal.aborted){req.destroy(Error('请求已取消'));return}const abort=()=>req.destroy(Error('请求已取消'));opts.signal.addEventListener('abort',abort,{once:true});req.on('close',()=>opts.signal.removeEventListener('abort',abort))}
  req.end(opts.body);
 });
}
function parseJSON(text){return JSON.parse(text.replace(/("(?:series_id|series_id_str|device_id|install_id|book_id|video_id|vid)"\s*:\s*)(\d{16,})/g,'$1"$2"'))}
async function anonymousIdentity(){if(!identityPromise)identityPromise=registerAnonymous().catch(e=>{identityPromise=null;throw e});return identityPromise}
async function api(path,payload,extra={},host='api5-normal-sinfonlineb.fqnovel.com',options={}){
 const dev=await anonymousIdentity(),body=payload==null?null:Buffer.from(JSON.stringify(payload));
 const qs=new URLSearchParams({aid:'8662',app_name:'novelread',version_code:'73532',version_name:'7.3.5.32',manifest_version_code:'73532',update_version_code:'73532',channel:'update_64',device_platform:'android',os:'android',ssmix:'a',device_type:'25053RT47C',device_brand:'Redmi',language:'zh',os_api:'36',os_version:'16',resolution:'1280*2772',dpi:'520',ac:'wifi',device_id:dev.device_id,iid:dev.install_id,...extra});qs.sort();
 const ts=Math.floor(Date.now()/1000);qs.set('_rticket',String(Date.now()));let url;
 for(let n=0;n<24;n++){url='https://'+host+path+'?'+qs; if(PureSign.branchOf(url,body,ts)!==1)break;qs.set('_rticket',String(Number(qs.get('_rticket'))+1))}
 const headers={'User-Agent':APP_UA,Accept:'application/json','Content-Type':'application/json; charset=utf-8','X-XS-From-Web':'0','Sdk-Version':'2','X-SS-Req-Ticket':qs.get('_rticket'),...(body?{'X-SS-STUB':crypto.createHash('md5').update(body).digest('hex').toUpperCase()}:{}),...PureSign.sign(url,body,ts)};
 for(let n=0,attempts=3;n<attempts;n++){const r=await request(url,{method:body?'POST':'GET',headers,body,timeout:Math.min(12000,Number(options.timeout)||12000)});if(r.status!==200)throw Error('播放接口 HTTP '+r.status);if(r.data.length){const x=parseJSON(r.data.toString());if(Number(x.code||x.Code||0)!==0)throw Error('播放接口业务错误 '+(x.code||x.Code));return x}if(n<attempts-1)await new Promise(r=>setTimeout(r,300*(n+1)))}
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
// Search sessions retain the upstream offset separately from JSTV page numbers.
const searchCursors=new Map();
function searchText(value){
 // JSTV NodeMobile has no ICU: avoid Unicode property escapes and native NFKC.
 return String(value||'').replace(/[\uFF01-\uFF5E]/g,c=>String.fromCharCode(c.charCodeAt(0)-0xFEE0)).replace(/[\s\u00B7\u0021-\u002F\u003A-\u0040\u005B-\u0060\u007B-\u007E\u2000-\u206F\u2E00-\u2E7F\u3000-\u303F]/g,'').toLowerCase();
}
function seasonNumber(value){
 if(/^\d+$/.test(value))return Number(value);
 const digits={'零':0,'〇':0,'一':1,'二':2,'两':2,'三':3,'四':4,'五':5,'六':6,'七':7,'八':8,'九':9};let total=0,current=0;
 for(const c of value){if(c in digits)current=digits[c];else if(c==='十'){total+=(current||1)*10;current=0}else if(c==='百'){total+=(current||1)*100;current=0}else return NaN}return total+current;
}
function seasonInfo(title){
 const name=String(title||'').trim(),match=name.match(/第([零〇一二两三四五六七八九十百\d]+)季$/)||name.match(/(\d+)$/);
 if(!match)return {stem:name,key:searchText(name),season:1,style:'plain'};
 const stem=name.slice(0,match.index).trim(),season=seasonNumber(match[1]);
 return {stem,key:searchText(stem),season,style:match[0].startsWith('第')?'season':'number'};
}
function searchVideos(tab){
 const out=[];
 const visit=(cell,depth=0)=>{
  if(!cell||typeof cell!=='object'||depth>5)return;
  const videos=Array.isArray(cell.video_data)?cell.video_data:cell.video_data?[cell.video_data]:[];
  for(const v of videos){
   const id=String(v.series_id||v.series_id_str||''),title=String(v.series_title||v.title||v.series_name||'').trim();
   if(!/^\d{10,24}$/.test(id)||!title||(Number(v.content_type)!==1004&&!(Number(v.episode_cnt)>0)))continue;
   out.push({vod_id:id,vod_name:title,vod_pic:String(v.cover||v.cover_url||v.series_cover||''),vod_remarks:Number(v.episode_cnt)>0?'全'+Number(v.episode_cnt)+'集':''});
  }
  if(cell.lynx_data){try{const nested=typeof cell.lynx_data==='string'?parseJSON(cell.lynx_data):cell.lynx_data;for(const row of nested.cell_data||[])visit(row,depth+1)}catch(e){}}
  for(const row of cell.cell_data||[])visit(row,depth+1);
 };
 for(const cell of tab.data||[])visit(cell);
 return out;
}
async function searchTab(query,cursor={offset:0}){
 const extra={query,count:'20',offset:String(cursor.offset||0),tab_type:'11',bookshelf_search_plan:'4',use_correct:'true',user_is_login:'0'};
 if(cursor.search_id)extra.search_id=cursor.search_id;if(cursor.passback)extra.passback=cursor.passback;
 const result=await api('/reading/bookapi/search/tab/v',null,extra),data=result.data||result;
 const tab=(data.search_tabs||[]).find(t=>Number(t.tab_type)===11);
 if(!tab)throw Error('搜索接口未返回剧目列表');
 return tab;
}
function addSearchRows(state,rows){for(const row of rows)if(!state.seen.has(row.vod_id)){state.seen.add(row.vod_id);state.rows.push(row)}}
async function nextSearchPage(state){
 if(!state.more)return;
 const tab=await searchTab(state.query,state),count=Array.isArray(tab.data)?tab.data.length:0;
 addSearchRows(state,searchVideos(tab));
 const next=Number(tab.next_offset),offset=Number.isFinite(next)&&next>state.offset?next:state.offset+count;
 state.more=[true,1,'1','true'].includes(tab.has_more)&&count>0&&offset>state.offset;
 state.offset=offset;state.search_id=String(tab.search_id||state.search_id||'');state.passback=String(tab.passback||'');
}
async function completeSearchSeasons(state){
 const keyword=searchText(seasonInfo(state.query).stem),families=new Map();
 for(const row of state.rows){const info=seasonInfo(row.vod_name);if(!info.key.includes(keyword)||!Number.isInteger(info.season)||info.season<1||info.season>200)continue;let family=families.get(info.key);if(!family){family={stem:info.stem,key:info.key,seasons:new Set(),style:'number'};families.set(info.key,family)}family.seasons.add(info.season);if(info.style!=='plain')family.style=info.style}
 // Only expand families supported by multiple real video records, never forum posts.
 const family=[...families.values()].filter(f=>f.seasons.size>=2).sort((a,b)=>b.seasons.size-a.seasons.size)[0];
 if(!family)return;
 const max=Math.max(...family.seasons),missing=[];
 for(let n=1;n<max;n++)if(!family.seasons.has(n))missing.push(n);
 const probes=[...missing.slice(-2),max+1];let extraNext=false;
 for(let i=0;i<probes.length&&i<4;i++){
  const n=probes[i],query=family.stem+(family.style==='season'?'第'+n+'季':String(n));
  try{
   const tab=await searchTab(query),matches=searchVideos(tab).filter(row=>{const info=seasonInfo(row.vod_name);return info.key===family.key&&info.season===n});
   addSearchRows(state,matches);
   if(n===max+1&&matches.length&&!extraNext){probes.push(max+2);extraNext=true}
  }catch(e){/* A supplementary search must not discard valid base results. */}
 }
}
function sortSearchRows(state){
 const keyword=searchText(seasonInfo(state.query).stem);
 const requested=seasonInfo(state.query),exact=searchText(state.query);
 state.rows.sort((a,b)=>{const x=seasonInfo(a.vod_name),y=seasonInfo(b.vod_name),an=searchText(a.vod_name),bn=searchText(b.vod_name);if((an===exact)!==(bn===exact))return an===exact?-1:1;const ax=an.includes(keyword),by=bn.includes(keyword);if(ax!==by)return ax?-1:1;if(requested.style!=='plain'&&ax&&by&&(x.season===requested.season)!==(y.season===requested.season))return x.season===requested.season?-1:1;if(x.key===y.key)return x.season-y.season;return 0});
}
async function search(body){
 const keyword=String(body.wd||'').trim().slice(0,80),pg=Math.max(1,Math.floor(Number(body.page||body.pg)||1)),limit=20;
 if(!keyword)return {list:[],page:pg,pagecount:pg,limit,total:0};
 let state=searchCursors.get(keyword);
 if(!state||Date.now()-state.created>180000||(pg===1&&!state.pending)){
  if(searchCursors.size>=32)searchCursors.delete(searchCursors.keys().next().value);
  state={query:keyword,created:Date.now(),rows:[],seen:new Set(),offset:0,passback:'',search_id:'',more:true,initialized:false,pending:null};searchCursors.set(keyword,state);
 }
 while(state.pending)await state.pending;
 const work=(async()=>{
  if(!state.initialized){
   try{
    await nextSearchPage(state);
    if(state.more){try{await nextSearchPage(state)}catch(e){}}
    await completeSearchSeasons(state);sortSearchRows(state);state.initialized=true;
   }catch(error){
    if(!state.rows.length){
     try{const data=await page('/search/'+encodeURIComponent(keyword)+'?page=1'),v=Object.values(data).find(x=>Array.isArray(x?.searchList));if(!v)throw error;addSearchRows(state,v.searchList.map(card).filter(x=>/^\d{10,24}$/.test(x.vod_id)&&x.vod_name));state.more=false;state.initialized=true}catch(e){searchCursors.delete(keyword);throw Error('搜索接口暂不可用，请稍后重试：'+error.message)}
    }
   }
  }
  let attempts=0;
  while(pg>1&&state.more&&state.rows.length<pg*limit&&attempts++<3){try{await nextSearchPage(state)}catch(e){if(state.rows.length<=(pg-1)*limit)throw e;break}}
 })();state.pending=work;
 try{await work}finally{if(state.pending===work)state.pending=null}
 const list=state.rows.slice((pg-1)*limit,pg*limit),known=Math.ceil(state.rows.length/limit),pagecount=Math.max(pg,known+(state.more?1:0));
 return {list,page:pg,pagecount,limit,total:state.rows.length+(state.more?1:0)};
}

async function detail(body){const id=String(body.id||'');if(!/^\d{10,24}$/.test(id))throw Error('剧集编号无效');const data=await page('/detail?series_id='+id),v=data.detail_page?.seriesDetail||Object.values(data).find(x=>x?.seriesDetail)?.seriesDetail;if(!v)throw Error('官网未返回剧集详情');const vids=(v.vid_list||[]).map(String).filter(x=>/^\d{10,24}$/.test(x));if(!vids.length)throw Error('官网未返回分集');return {list:[{...card(v),vod_id:id,type_name:(v.tags||[]).join(' / '),vod_content:String(v.series_intro||''),vod_remarks:'全'+vids.length+'集',vod_play_from:'自动 · 最高1080P$$$720P$$$480P',vod_play_url:[0,720,480].map(q=>vids.map((vid,i)=>'第'+(i+1)+'集$'+id+':'+vid+'|'+q).join('#')).join('$$$')}]}}
function contentKey(spade){const raw=Buffer.from(spade||'','base64');if(raw.length<3)throw Error('媒体密钥格式无效');const tag=(raw[0]^raw[1]^raw[2])-48,n=raw.length-tag-1;if(tag<1||n<33||n>=raw.length)throw Error('媒体密钥结构无效');const out=Buffer.alloc(n);let even=250,odd=85;for(let i=0;i<n;i++){const cur=raw[i+1],prev=i%2?odd:even;if(i%2)odd=cur;else even=cur;let x=i,count=0;for(;x;x>>>=1)count+=x&1;out[i]=((prev^cur)-21-count)&255}if(!/^[0-9a-fA-F]{32}$/.test(out.subarray(1,33).toString()))throw Error('媒体密钥版本不支持');return Buffer.from(out.subarray(1,33).toString(),'hex')}
function mediaAddress(v){let s=String(v||'').trim();if(!/^https?:\/\//.test(s))s=Buffer.from(s,'base64').toString();if(!/^https?:\/\//.test(s))return '';return s}
function decodedMediaAddress(value,seed){
 const direct=mediaAddress(value);if(direct)return direct;
 if(!seed||!value)return '';
 try{
  const raw=Buffer.from(String(value),'base64'),s=Buffer.from(String(seed),'base64');
  if(raw.length<20||raw[0]!==0xa8||raw[2]!==1||raw[3]!==0)return '';
  const sha=x=>crypto.createHash('sha512').update(x).digest(),h=sha(Buffer.concat([sha(s),REG_CONSTANTS]));
  const cipher=crypto.createDecipheriv('aes-128-cbc',h.subarray(0,16),h.subarray(16,32));cipher.setAutoPadding(false);
  let data=Buffer.concat([cipher.update(raw.subarray(4,4+Math.floor((raw.length-4)/16)*16)),cipher.final()]);
  const n=data[data.length-1];if(n>=1&&n<=16&&data.subarray(-n).every(x=>x===n))data=data.subarray(0,-n);
  while(data.length&&data[data.length-1]===0)data=data.subarray(0,-1);
  return mediaAddress(data.toString('utf8'));
 }catch(e){return ''}
}
function compatibleMediaVariants(data){
 return Object.values(data?.video_list||{}).filter(v=>v&&typeof v==='object').map(v=>{
  const meta=v.video_meta||{},enc=v.encrypt_info||{},spade=enc.spade_a||v.spade_a||'';
  const codec=String(meta.codec_type||v.codec_type||'').toLowerCase();
  const named=parseInt(meta.definition||v.definition||v.quality_desc||v.quality);
  const width=Number(meta.vwidth||v.vwidth||v.width),height=Number(meta.vheight||v.vheight||v.height);
  const quality=named||Math.min(width||Infinity,height||Infinity);
  const backups=Array.isArray(v.backup_url_list)?v.backup_url_list:[];
  const url=[v.main_url,v.backup_url,v.backup_url_1,...backups].map(value=>decodedMediaAddress(value,data.key_seed)).find(Boolean);
  return {url,spade,encrypted:!!enc.encrypt||!!spade,codec,quality:Number.isFinite(quality)?quality:0};
 }).filter(v=>v.url&&!['bytevc2','bvc2'].includes(v.codec));
}
function fallbackMediaAddress(value){
 if(Array.isArray(value))return fallbackMediaAddress(value[0]);
 if(value&&typeof value==='object')return fallbackMediaAddress(value.fallback_api);
 if(typeof value!=='string')return '';
 const text=value.trim();
 if(text.startsWith('{')||text.startsWith('[')){
  try{return fallbackMediaAddress(parseJSON(text))}catch(e){return ''}
 }
 return text;
}

async function modelMediaVariants(model,quality,signal){
 const direct=compatibleMediaVariants(model);
 const hasQuality=rows=>rows.some(v=>!quality||(v.quality>0&&v.quality<=quality));
 if(hasQuality(direct))return direct;
 const fallback=fallbackMediaAddress(model.fallback_api);
 if(!fallback.startsWith('https://'))return [];
 const original=new URL(fallback);
 if(!['snssdk.com','fqnovel.com','bytedance.com','bytecdn.cn','volcvideo.com'].some(host=>original.hostname===host||original.hostname.endsWith('.'+host)))throw Error('媒体信息地址不受支持');
 // Models with no inline media use the URL provided by the platform first.
 // Keep 1.0.5's codec negotiation for models without a compatible stream.
 const codecs=Object.keys(model.video_list||{}).length?['1','0']:[null,'1','0'];
 for(const codec of codecs){
  const u=new URL(original.href);
  if(codec!==null){
   u.searchParams.set('codec_type',codec);
   u.searchParams.delete('force_fids');
   u.searchParams.delete('encode_user_tag');
  }
  const r=await request(u.href,{headers:{'User-Agent':APP_UA,Referer:'https://novel.snssdk.com/'},timeout:5000,signal});
  checkPlaybackResponse(r,'媒体信息接口');
  if(!r.data.toString().trim())continue;
  const response=parseJSON(r.data.toString());
  checkPlaybackCode(response,'媒体信息接口');
  checkPlaybackCode(response.video_info,'媒体信息接口');
  const info=response.video_info?.data;
  if(!info)continue;
  if(model.video_id&&info.video_id&&String(model.video_id)!==String(info.video_id))throw Error('媒体信息与本集不匹配');
  const rows=compatibleMediaVariants(info);
  if(hasQuality(rows))return rows;
 }
 return [];
}

const PLAYER_API='https://api5-normal-sinfonlinea.fqnovel.com/novel/player/multi_video_model/player/v1';
const VIDEO_TAB_API='https://api5-normal-sinfonlineb.fqnovel.com/reading/bookapi/video_tab/multi_video_model/v1/';
const V5_PLAYER_UA = 'com.phoenix.read/73932 (Linux; U; Android 12; zh_CN_#Hans; '
  + 'PGT-AN10; Build/V417IR;tt-ok/3.12.13.20)';
const VIDEO_TAB_UA = 'com.phoenix.read/71332 (Linux; U; Android 16; zh_CN; 25053RT47C; '
  + 'Build/BP2A.250605.031.A3; Cronet/TTNetVersion:04657795 2026-01-23 '
  + 'QuicVersion:c67e9834 2025-09-08)';

const V5_PLAYER_DEVICE = {
  aid: '8662',
  app_name: 'novelread',
  version_code: '74332',
  version_name: '7.4.3.32',
  channel: 'vivo_8662_64',
  device_platform: 'android',
  device_type: 'PGT-AN10',
  os_version: '12',
  update_version_code: '74332',
};

const VIDEO_TAB_DEVICE = {
  ac: 'wifi',
  channel: 'update_64',
  aid: '8662',
  app_name: 'novelread',
  version_code: '73932',
  version_name: '7.3.9.32',
  device_platform: 'android',
  os: 'android',
  ssmix: 'a',
  device_type: '25053RT47C',
  device_brand: 'Redmi',
  language: 'zh',
  os_api: '36',
  os_version: '16',
  manifest_version_code: '73932',
  resolution: '1280*2772',
  dpi: '520',
  update_version_code: '73932',
  host_abi: 'arm64-v8a',
  dragon_device_type: 'phone',
  pv_player: '73932',
  compliance_status: '0',
  need_personal_recommend: '1',
  player_so_load: '1',
  is_android_pad_screen: '0',
};

function checkPlaybackResponse(response,endpoint){
 const retryAfter=response.headers['retry-after'];
 if(response.status===429||retryAfter){
  const seconds=Number(retryAfter);
  const time=retryAfter?(Number.isFinite(seconds)?Date.now()+1000*seconds:Date.parse(retryAfter)):NaN;
  playbackRetryAt=Number.isFinite(time)&&time>Date.now()?time:Date.now()+60000;
  throw Error(endpoint+'请求受限，请稍后重试');
 }
 if(response.status!==200)throw Error(endpoint+' HTTP '+response.status);
}

function checkPlaybackCode(data,endpoint){
 const code=[data?.code,data?.Code].map(value=>Number(value??0)).find(value=>value!==0);
 if(code!==undefined)throw Error(endpoint+'业务错误 '+code);
}

function modelForEpisode(text,vid){
 const result=parseJSON(text);
 checkPlaybackCode(result,'播放接口');
 const data=result?.data;
 const rows=data?.['1004']??data?.video_model_data??data;
 const entry=rows&&Object.prototype.hasOwnProperty.call(rows,vid)?rows[vid]:null;
 let model=entry?.video_model;
 if(typeof model==='string'){
  try{model=parseJSON(model)}catch(e){model=parseJSON(Buffer.from(model,'base64').toString())}
 }
 if(!model||typeof model!=='object'||(!model.video_list&&!model.fallback_api))throw Error('播放接口未返回本集可用视频');
 return model;
}

async function requestPlaybackModel(vid,signal){
 const registration=await registerAnonymous(signal);
 const device={iid:registration.install_id,cdid:registration.cdid,device_id:registration.device_id};
 const body=zlib.gzipSync(Buffer.from(JSON.stringify({
  biz_param:{
   detail_page_version:0,device_level:1,disable_digg_stat:false,disable_video_relate_book:false,
   need_all_video_definition:true,need_mp4_align:false,use_os_player:false,use_server_dns:false,video_platform:1024,
  },
  mixed_video_id_map:{'1004':[vid]},
  dr_scene:'player',
 })));
 const primary=PureSign.signPlaybackV5(PLAYER_API,{...V5_PLAYER_DEVICE,...device},body,Date.now());
 const result=await request(primary.url,{
  method:'POST',body,followRedirect:false,timeout:7000,signal,
  headers:{'User-Agent':V5_PLAYER_UA,Accept:'application/json','Content-Encoding':'gzip','Content-Length':String(body.length),...primary.headers},
 });
 checkPlaybackResponse(result,'播放接口');
 const text=result.data.toString();
 if(text.trim())return modelForEpisode(text,vid);

 // A successful response with no body gets one retry on the video-tab API.
 const tab=PureSign.signPlaybackV5(VIDEO_TAB_API,{
  ...VIDEO_TAB_DEVICE,...device,video_id:vid,video_id_type:'0',device_level:'1',
  need_all_video_definition:'1',need_mp4_align:'0',use_os_player:'0',video_platform:'1024',source:'0',from_video_id:'',
 },null,Date.now());
 const recovered=await request(tab.url,{
  followRedirect:false,timeout:7000,signal,
  headers:{'User-Agent':VIDEO_TAB_UA,'Accept-Language':'zh-CN,zh;q=0.9',...tab.headers},
 });
 checkPlaybackResponse(recovered,'备用播放接口');
 const retryText=recovered.data.toString();
 if(!retryText.trim())throw Error('红果播放接口暂未返回内容，请稍后重试');
 return modelForEpisode(retryText,vid);
}

function resolveMedia(vid,quality,lifetime){
 const pending=playbackQueue.then(async()=>{
  if(lifetime.aborted)throw Error('播放请求已取消');
  if(Date.now()<playbackRetryAt)throw Error('红果播放接口请求受限，请稍后重试');
  const wait=nextPlaybackAt-Date.now();
  if(wait>0)await new Promise(resolve=>setTimeout(resolve,wait));
  const signal=AbortSignal.any([lifetime,AbortSignal.timeout(22000)]);
  try{
   const model=await requestPlaybackModel(vid,signal);
   const rows=await modelMediaVariants(model,quality,signal);
   const selected=rows.filter(v=>!quality||(v.quality>0&&v.quality<=quality)).sort((a,b)=>b.quality-a.quality)[0];
   if(!selected)throw Error('本集暂未返回兼容的所选画质');
   if(selected.encrypted&&!selected.spade)throw Error('未返回媒体密钥');
   return {...selected,key:selected.spade?contentKey(selected.spade):null};
  }finally{if(!lifetime.aborted)nextPlaybackAt=Date.now()+1000}
 });
 playbackQueue=pending.catch(()=>{});
 return pending;
}

async function preparePlayback(vid,quality,cacheKey){
 const lifetime=playbackLifetime.signal;
 const media=await resolveMedia(vid,quality,lifetime);
 const item={...media,created:Date.now(),id:crypto.randomBytes(12).toString('hex'),ready:false};
 await prepare(item,lifetime);
 if(lifetime.aborted)throw Error('播放请求已取消');
 if(mediaCache.size>=8)mediaCache.delete(mediaCache.keys().next().value);
 mediaCache.set(cacheKey,item);
 return item;
}

async function play(body){
 const m=String(body.id||'').match(/^(\d{10,24}):(\d{10,24})\|(0|480|720)$/);
 if(!m)throw Error('分集编号无效');
 const [, ,vid,quality]=m,cacheKey=vid+'|'+quality;
 let item=mediaCache.get(cacheKey);
 if(!item||Date.now()-item.created>1200000){
  if(!pendingMedia.has(cacheKey)){
   const pending=preparePlayback(vid,Number(quality),cacheKey).finally(()=>{
    if(pendingMedia.get(cacheKey)===pending)pendingMedia.delete(cacheKey);
   });
   pendingMedia.set(cacheKey,pending);
  }
  item=await pendingMedia.get(cacheKey);
 }
 const address=server.address();
 return {parse:0,url:'http://127.0.0.1:'+address.port+PREFIX+'/video/'+item.id+'.mp4',header:{'User-Agent':'JSTV-Hongguo/1.0'},format:'video/mp4'};
}
function boxes(b,start=0,end=b.length){const out=[];for(let p=start;p+8<=end;){let size=b.readUInt32BE(p),head=8;const type=b.toString('ascii',p+4,p+8);if(size===1){if(p+16>end)break;size=Number(b.readBigUInt64BE(p+8));head=16}else if(!size)size=end-p;if(size<head||p+size>end)break;out.push({type,start:p,data:p+head,end:p+size,size});p+=size}return out}
function child(b,box,type){return boxes(b,box.data,box.end).find(x=>x.type===type)}
async function range(url,start,end,signal){const r=await request(url,{headers:{Range:'bytes='+start+'-'+end,Referer:'https://novel.snssdk.com/','User-Agent':APP_UA,'Accept-Encoding':'identity'},timeout:15000,signal,limit:Math.max(end-start+1,512*1024)+1024});if(r.status!==206)throw Error('视频 CDN 未返回分段数据 ('+r.status+')');if(r.data.length!==end-start+1)throw Error('视频 CDN 分段长度异常');return r}
function indexTrack(head,track){const mdia=child(head,track,'mdia'),minf=mdia&&child(head,mdia,'minf'),stbl=minf&&child(head,minf,'stbl');if(!stbl)return [];const sz=child(head,stbl,'stsz'),co=child(head,stbl,'stco')||child(head,stbl,'co64'),sc=child(head,stbl,'stsc'),iz=child(head,stbl,'saiz'),io=child(head,stbl,'saio');if(!sz||!co||!sc||!iz||!io)return [];const count=head.readUInt32BE(sz.data+8),fixed=head.readUInt32BE(sz.data+4),sizes=Array.from({length:count},(_,i)=>fixed||head.readUInt32BE(sz.data+12+i*4));const nco=head.readUInt32BE(co.data+4),offsets=Array.from({length:nco},(_,i)=>co.type==='co64'?Number(head.readBigUInt64BE(co.data+8+i*8)):head.readUInt32BE(co.data+8+i*4)),nsc=head.readUInt32BE(sc.data+4),chunks=Array.from({length:nsc},(_,i)=>({first:head.readUInt32BE(sc.data+8+i*12),samples:head.readUInt32BE(sc.data+12+i*12)}));const flags=head.readUInt32BE(iz.data)&0xffffff,izStart=iz.data+4+(flags&1?8:0),auxDefault=head[izStart],auxCount=head.readUInt32BE(izStart+1);const ioFlags=head.readUInt32BE(io.data)&0xffffff,ioStart=io.data+4+(ioFlags&1?8:0),auxOffset=head[io.data]===1?Number(head.readBigUInt64BE(ioStart+4)):head.readUInt32BE(ioStart+4);if(auxCount!==count)throw Error('MP4 加密采样数量不一致');let sample=0,aux=auxOffset,scIndex=0;const rows=[];for(let ci=0;ci<offsets.length;ci++){while(scIndex+1<chunks.length&&chunks[scIndex+1].first<=ci+1)scIndex++;let pos=offsets[ci];for(let j=0;j<chunks[scIndex].samples&&sample<count;j++,sample++){const auxSize=auxDefault||head[izStart+5+sample];if(auxSize!==8&&auxSize!==16)throw Error('暂不支持此 MP4 子采样加密格式');if(aux+auxSize>head.length)throw Error('MP4 加密索引不在文件头');const iv=Buffer.alloc(16);head.copy(iv,0,aux,aux+auxSize);rows.push({start:pos,end:pos+sizes[sample],iv});pos+=sizes[sample];aux+=auxSize}}if(sample!==count)throw Error('MP4 采样索引不完整');return rows}
function replaceTags(head,from,to){const a=Buffer.from(from),b=Buffer.from(to);for(let p=0;(p=head.indexOf(a,p))>=0;p+=4)b.copy(head,p)}
async function prepare(item,signal){const first=await request(item.url,{headers:{Range:'bytes=0-262143',Referer:'https://novel.snssdk.com/','User-Agent':APP_UA,'Accept-Encoding':'identity'},timeout:15000,limit:512*1024,signal});if(first.status!==206)throw Error('视频 CDN 暂不可用 ('+first.status+')');const total=Number(String(first.headers['content-range']||'').split('/')[1]);if(!total)throw Error('未取得视频长度');let data=first.data;let moov;for(let p=0;p+8<=data.length;){const size=data.readUInt32BE(p),type=data.toString('ascii',p+4,p+8);if(size<8||p+size>8*1024*1024)throw Error('MP4 文件头不兼容');if(type==='moov'){if(p+size>data.length)data=Buffer.concat([data,(await range(item.url,data.length,p+size-1,signal)).data]);moov={start:p,data:p+8,end:p+size};break}p+=size}if(!moov)throw Error('未找到 MP4 视频索引');item.head=Buffer.from(data.subarray(0,moov.end));item.total=total;item.samples=[];if(item.key){for(const trak of boxes(item.head,moov.data,moov.end).filter(x=>x.type==='trak'))item.samples.push(...indexTrack(item.head,trak));if(!item.samples.length)throw Error('未找到加密采样索引');item.samples.sort((a,b)=>a.start-b.start);replaceTags(item.head,'encv',item.codec==='h264'||item.codec==='avc1'?'avc1':'hvc1');replaceTags(item.head,'enca','mp4a');for(let p=0;(p=item.head.indexOf(Buffer.from('sinf'),p))>=0;p+=4)item.head.write('free',p)}item.ready=true;return item}
function transform(item,start,data){const out=Buffer.from(data),end=start+out.length;if(start<item.head.length)item.head.copy(out,0,start,Math.min(end,item.head.length));if(!item.key)return out;let low=0,high=item.samples.length;while(low<high){const mid=(low+high)>>1;if(item.samples[mid].start<=start)low=mid+1;else high=mid}for(let i=Math.max(0,low-1);i<item.samples.length;i++){const sample=item.samples[i];if(sample.start>=end)break;const a=Math.max(start,sample.start),b=Math.min(end,sample.end);if(a>=b)continue;const offset=a-sample.start,blocks=Math.floor(offset/16),skip=offset%16,counter=(BigInt('0x'+sample.iv.toString('hex'))+BigInt(blocks))&((1n<<128n)-1n),iv=Buffer.from(counter.toString(16).padStart(32,'0'),'hex'),dec=crypto.createDecipheriv('aes-128-ctr',item.key,iv);if(skip)dec.update(Buffer.alloc(skip));Buffer.concat([dec.update(out.subarray(a-start,b-start)),dec.final()]).copy(out,a-start)}return out}
async function serveVideo(req,res,id){const item=[...mediaCache.values()].find(x=>x.id===id);if(!item){res.writeHead(410);res.end();return}let start=0,end=item.total-1;const header=req.headers.range;if(header){const m=header.match(/^bytes=(\d*)-(\d*)$/);if(!m){res.writeHead(416,{'Content-Range':'bytes */'+item.total});res.end();return}if(!m[1]){start=Math.max(0,item.total-Number(m[2]));}else {start=Number(m[1]);if(m[2])end=Math.min(end,Number(m[2]));}if(!Number.isSafeInteger(start)||start<0||start>end||start>=item.total){res.writeHead(416,{'Content-Range':'bytes */'+item.total});res.end();return}}const headers={'Content-Type':'video/mp4','Content-Length':end-start+1,'Accept-Ranges':'bytes','Cache-Control':'no-store'};if(header)headers['Content-Range']='bytes '+start+'-'+end+'/'+item.total;res.writeHead(header?206:200,headers);if(req.method==='HEAD'){res.end();return}const controller=new AbortController();res.once('close',()=>controller.abort());try{for(let pos=start;pos<=end&&!res.destroyed;){const last=Math.min(end,pos+512*1024-1);let buf;if(last<item.head.length)buf=item.head.subarray(pos,last+1);else buf=transform(item,pos,(await range(item.url,pos,last,controller.signal)).data);if(!res.write(buf))await new Promise(resolve=>{const done=()=>{res.removeListener('drain',done);res.removeListener('close',done);resolve()};res.once('drain',done);res.once('close',done)});pos=last+1}if(!res.destroyed)res.end()}catch(e){if(!res.destroyed)res.destroy()}}
function send(res,data,status=200){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data))}
function config(){return {video:{sites:[{key:'nodejs_hongguo_local',name:'红果短剧·独立版',type:3,api:PREFIX,searchable:1,quickSearch:1,filterable:1}]},read:{sites:[]},comic:{sites:[]},music:{sites:[]},pan:{sites:[]},color:[]}}
async function handler(req,res){try{const path=new URL(req.url,'http://127.0.0.1').pathname;if(req.method==='OPTIONS'){res.writeHead(204);res.end();return}if(path==='/config'||path==='/full-config')return send(res,config());if(path==='/check')return send(res,{run:true});if(path==='/website'||path==='/website/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end('<!doctype html><meta charset="utf-8"><title>红果短剧独立源</title><h1>红果短剧·独立版</h1><p>1.0.6 · 2026-11-20</p><p>无需账号登录。匿名设备身份与临时播放信息只留在内存中。</p><p>在 JSTV「我的扩展」选择本源即可搜索和观看。</p>');return}const video=path.match(new RegExp('^'+PREFIX+'/video/([a-f0-9]{24})\\.mp4$'));if(video&&['GET','HEAD'].includes(req.method))return await serveVideo(req,res,video[1]);if(req.method!=='POST'||!path.startsWith(PREFIX+'/'))return send(res,{error:'Not Found'},404);const chunks=[];let size=0;for await(const b of req){size+=b.length;if(size>65536)return send(res,{error:'请求过大'},413);chunks.push(b)}const body=parseJSON(Buffer.concat(chunks).toString()||'{}'),action=path.slice(PREFIX.length+1),actions={init:async()=>({}),home,category,search,detail,play};if(!actions[action])return send(res,{error:'Not Found'},404);send(res,await actions[action](body))}catch(e){if(!res.headersSent)send(res,{error:String(e.message||'源请求失败'),message:String(e.message||'源请求失败'),list:[]},502);else res.destroy()}}
async function start(options={}){if(server)await stop();playbackLifetime=new AbortController();server=typeof globalThis.catServerFactory==='function'?globalThis.catServerFactory(handler):http.createServer(handler);const port=Number(options.port)||9988;await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve)});return server}
async function stop(){playbackLifetime?.abort();if(server){const old=server;server=null;if(typeof old.closeAllConnections==='function')old.closeAllConnections();await new Promise(r=>old.close(r))}agent.destroy();mediaCache.clear();pageCache.clear();searchCursors.clear();identityPromise=null;pendingMedia.clear();playbackQueue=Promise.resolve();nextPlaybackAt=0;playbackRetryAt=0}
module.exports={start,stop,getServer:()=>server};

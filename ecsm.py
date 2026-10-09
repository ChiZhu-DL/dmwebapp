# -*- coding: utf-8 -*-
"""
ecsm.py -- 「动漫共和国」libmagic_cipher.so 的 ECSM/chunkenc 层纯 Python 编解码器。
仅用标准库。所有常量/算法均逐条核对自反汇编。

逆向来源 (libmagic_cipher.so, arm64-v8a):
  - 单块 opcode 链加密 zqmc_ev3_chunkenc = 0x249C4
  - 多块解码 (容器)                      = 0x25088
  - 单块解码                             = 0x25940
  - opcode 分发器 zqmc_mc_process        = 0x0EEAC
  - 容器头写入                            = encrypt_v3(0x181D4) 内 0x19448..0x19718
  - opcode 实现: op1 0x1074C(解)/内联(加), op2 0x1097C, op3 0x10EC0/0x11314,
    op4 块 0x226E4(加)/0x227E4(解)/0x11954(全解), op5 0x22928, op6 0x22D58+内联/0x12190

============================ 容器格式 ============================
明文 <= 0x10000 (64KB): encoded = 单块 opcode 链输出, 无容器头 (帧 multiFlag=0)。
明文 >  0x10000:        encoded = "ECSM" 容器 (帧 multiFlag=1):

  offset 0..3   "ECSM"  (45 43 53 4D)
  offset 4..7   00 01 00 00   (u32 LE 0x100 常量, 解码端不校验)
  offset 8..11  chunkCount, u32 BE   (= (len+0xFFFF)>>16)
  随后 chunkCount 组:
        u32 BE  chunkEncodedLen
        chunkEncodedLen 字节 = encode_chunk(明文块)
  明文切成 0x10000 字节一块 (最后一块为余数), 每块独立用同一组
  (ids, key segments) 加密; 解码端逐块校验 offset+len<=total 并拼接。

============================ opcode 链 ============================
encode_chunk: buf = payload; for i in 0..segCount-1 (正序):
              buf = mc_process(directory[ids[i]], keys[i], buf, enc=1)
decode_chunk: for i in segCount-1..0 (逆序), enc=0。
mc_process (0xEEAC) 按 opcode 分发, keyLen 强制校验:
  op1 keyLen==8   链式XOR-rotate; 加密内联于 0xEEAC, 解密 0x1074C
  op2 keyLen==16  变体RC4 (0x1097C), 加解密同一函数
  op3 无钥        自定义字母表 Base64 (加 0x10EC0 / 解 0x11314), 无 '=' 填充
  op4 keyLen==16  TEA 变体; 加: PKCS7(8)填充 + 0x226E4 逐块; 解: 0x11954 + 0x227E4 + 去填充
  op5 keyLen==44  魔改 ChaCha20 流密码 (0x22928), 加解密同一 keystream
  op6 keyLen==16  Blowfish, 自定义 P/S 初始表; 加: 0x22D58 + 填充 + 内联块加密;
                  解: 0x12190 (含去填充)

注: 本 .so 内另有 SHA-512 (0x23FBC/0x24620, K 表@0x4278) 与软件 AES-128
(0x25F98/0x26254, S盒@0x44FC, Rcon@0x45FC), 属 HMAC 辅助 / maes 白盒等其它
子系统, 不在 ECSM 编解码路径上。

目录 (id -> opcode): native 由 magic_sdk_init 装载到 0x2A9F0
(计数 0x2A9EC, 项 = [id u8][opcode u8][len u16])。本模块默认恒等映射,
如 init 数据给出其它映射请通过 directory= 传入。

接口:
  encode(segments, payload, directory=None)   # segments = [(id, key_bytes), ...]
  decode(segments, blob,     directory=None) # 自动识别 "ECSM" 容器 / 单块
  encode_chunk / decode_chunk / build_container / parse_container
"""

import struct

M32 = 0xFFFFFFFF
CHUNK = 0x10000

def _rol32(v, n):
    v &= M32
    return ((v << n) | (v >> (32 - n))) & M32

# ---------------------------------------------------------------- op1
def op1_enc(key, data):
    """0xEEAC 内联; prev 初值 0x5A, 链用密文字节, 计数 (prev+i)&0xFF, ROL8×3."""
    out = bytearray(len(data))
    prev = 0x5A
    for i, c in enumerate(data):
        b = key[i & 7] ^ c ^ ((prev + i) & 0xFF)
        out[i] = ((b << 3) | (b >> 5)) & 0xFF
        prev = out[i]
    return bytes(out)

def op1_dec(key, data):
    """0x1074C; prev 为上一密文字节."""
    out = bytearray(len(data))
    prev = 0x5A
    for i, c in enumerate(data):
        b = ((c >> 3) | (c << 5)) & 0xFF
        out[i] = key[i & 7] ^ b ^ ((prev + i) & 0xFF)
        prev = c
    return bytes(out)

# ---------------------------------------------------------------- op2
def op2(key, data):
    """0x1097C 变体RC4。初始 S = [(i+13)&0xFF] (16 个 xmmword 静态表拼接)。
    KSA: t = ((i ^ 0xFFFFFFAA) + prev + S[i] + key[i&0xF]) & 0xFFFFFFFF;
         k = t & 0xFF; swap S[i],S[k]; prev = t (32位, 不截断)。
    PRGA: i 初值 0x11, j 初值 0x22;
         t = (i + j + 1); i2 = t & 0xFF; a = S[i2];
         j = (a + j) & 0xFF; swap S[i2],S[j];
         t2 = ((S[i2] + a) & 0xFF) ^ key[i2 & 0xF];
         out = S[t2 & 0xFF] ^ data[n]; i = t (32位全值, MOV W9,W12)。
    """
    S = list(range(13, 256)) + list(range(0, 13))
    prev = 0
    for i in range(256):
        a = S[i]
        t = ((i ^ 0xFFFFFFAA) + prev + a + key[i & 0xF]) & M32
        k = t & 0xFF
        S[i] = S[k]
        S[k] = a
        prev = t
    out = bytearray(len(data))
    ii, jj = 0x11, 0x22
    for n, c in enumerate(data):
        i2 = (ii + jj + 1) & 0xFF          # W12 = ii+jj+1, AND 0xFF (ii 保持截断)
        ii = i2
        a = S[i2]
        jj = (a + jj) & 0xFF
        S[i2] = S[jj]
        S[jj] = a
        t = ((S[i2] + a) & 0xFF) ^ key[n & 0xF]   # 0x10D78: EOR key[n&0xF]
        out[n] = S[t & 0xFF] ^ c                  # 0x10D7C: W16=data[n]; 0x10D90 EOR
    return bytes(out)

# ---------------------------------------------------------------- op3
# 字母表 = blob@0x4908 解密: alpha[i] = blob[21+i] ^ blob[i%21] (0x27564)
_B64_BLOB = bytes.fromhex(
    "5d527a81afd963f1770fd4f36d07887631c909a9413a3a13ebc4b50e9f187f"
    "a5811e73fd0046b170d3001f113ec4e99e2bb83d4498be2348d827639a5dfc"
    "170a0a23db9fe851c2433ae2c4553ea35950ab6acd243b5229085060a61842"
    "2798dc")
ALPHABET = bytes((_B64_BLOB[21 + i] ^ _B64_BLOB[i % 21]) & 0xFF for i in range(64))
# = "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdef"
_REV = [0] * 256
for _i, _c in enumerate(ALPHABET):
    _REV[_c] = _i

def op3_enc(data):
    """0x10EC0。无 '=' 填充: len%3==1 -> 输出 2 字符, ==2 -> 3 字符."""
    n = len(data)
    out = bytearray()
    for o in range(0, n - n % 3, 3):
        b0, b1, b2 = data[o], data[o + 1], data[o + 2]
        w = (b0 << 16) | (b1 << 8) | b2
        out.append(ALPHABET[b0 >> 2])
        out.append(ALPHABET[(w >> 12) & 0x3F])
        out.append(ALPHABET[(w >> 6) & 0x3F])
        out.append(ALPHABET[w & 0x3F])
    r = n % 3
    if r == 1:
        b0 = data[-1]
        out.append(ALPHABET[b0 >> 2])
        out.append(ALPHABET[(b0 & 3) << 4])
    elif r == 2:
        b0, b1 = data[-2], data[-1]
        out.append(ALPHABET[b0 >> 2])
        out.append(ALPHABET[((b0 & 3) << 4) | (b1 >> 4)])
        out.append(ALPHABET[(b1 & 0xF) << 2])
    return bytes(out)

def op3_dec(data):
    """0x11314."""
    n = len(data)
    if n % 4 == 1:
        raise ValueError("op3_dec: bad length %d" % n)
    out = bytearray()
    full = n // 4
    for o in range(full):
        w = ((_REV[data[o * 4]] << 18) | (_REV[data[o * 4 + 1]] << 12) |
             (_REV[data[o * 4 + 2]] << 6) | _REV[data[o * 4 + 3]])
        out += bytes(((w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF))
    r = n - full * 4
    if r == 3:
        w = ((_REV[data[-3]] << 18) | (_REV[data[-2]] << 12) |
             (_REV[data[-1]] << 6))
        out += bytes(((w >> 16) & 0xFF, (w >> 8) & 0xFF))
    elif r == 2:
        w = (_REV[data[-2]] << 18) | (_REV[data[-1]] << 12)
        out.append((w >> 16) & 0xFF)
    return bytes(out)

# ---------------------------------------------------------------- op4
_TEA_C1 = 0xB7E15163                       # 和常量 (W11)
_TEA_DELTA = 0x481EAE9D                    # == -C1 mod 2^32 (解密端累加)

def _tea_enc_block(key, block):
    # native 以大端 u32 读取密钥字 (mc_process 0x0F748 对 key 做了 REV)
    k0, k1, k2, k3 = struct.unpack(">4I", key)
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    s = 0
    for _ in range(32):
        f = (k0 + ((v1 << 5) & M32)) & M32
        f ^= (k1 + (v1 >> 3)) & M32
        f ^= (v1 + _TEA_C1 + s) & M32
        s = (s + _TEA_C1) & M32
        v0 = (v0 + f) & M32
        f = (k2 + ((v0 << 5) & M32)) & M32
        f ^= (k3 + (v0 >> 3)) & M32
        f ^= (v0 + s) & M32
        v1 = (v1 + f) & M32
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")

def _tea_dec_block(key, block):
    k0, k1, k2, k3 = struct.unpack(">4I", key)
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    K = (32 * _TEA_C1) & M32               # 0xFC2A2C60
    for _ in range(32):
        f = (k2 + ((v0 << 5) & M32)) & M32
        f ^= (v0 + K) & M32
        f ^= (k3 + (v0 >> 3)) & M32
        v1 = (v1 - f) & M32
        kn = K
        K = (K + _TEA_DELTA) & M32
        f = (k0 + ((v1 << 5) & M32)) & M32
        f ^= (v1 + kn) & M32
        f ^= (k1 + (v1 >> 3)) & M32
        v0 = (v0 - f) & M32
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")

def _pad8(data):
    pad = 8 - (len(data) & 7)              # len%8==0 时补 8 个 0x08
    return data + bytes([pad]) * pad

def _unpad(data, tag):
    if not data:
        raise ValueError("%s: empty" % tag)
    pad = data[-1]
    if pad < 1 or pad > len(data) or any(b != pad for b in data[len(data) - pad:]):
        raise ValueError("%s: bad padding" % tag)
    return data[:len(data) - pad]

def op4_enc(key, data):
    padded = _pad8(data)
    return b"".join(_tea_enc_block(key, padded[i:i + 8])
                    for i in range(0, len(padded), 8))

def op4_dec(key, data):
    if len(data) == 0 or len(data) & 7:
        raise ValueError("op4_dec: bad length")
    return _unpad(b"".join(_tea_dec_block(key, data[i:i + 8])
                           for i in range(0, len(data), 8)), "op4")

# ---------------------------------------------------------------- op5
# 0x22928。状态 16 字:
#   x0="mAgic" x1..x4=key[0:16]LE  x5=" CH"  x6..x9=key[16:32]LE
#   x10="ACha" x11=n[0:4] x12=n[4:8] x13=counter(独立参数) x14=" ROu" x15=n[8:12]
#   (n = key[32:44]; mc_process 的块计数器从 1 开始逐块 +1)
# QR(a,b,c,d): a+=b; c^=a; c<<<=15; d+=c; b^=d; b<<<=11;
#              a+=b; c^=a; c<<<=9;  d+=c; b^=d; b<<<=6
# 列/对角分组 (c/d 相对标准 ChaCha 交换; 对角 = (A[j],B[j+1],D[j+3],C[j+2])):
_COLS = ((0, 1, 13, 6), (5, 2, 11, 7), (10, 3, 12, 8), (14, 4, 15, 9))
_DIAGS = ((0, 2, 15, 8), (5, 3, 13, 9), (10, 4, 11, 6), (14, 1, 12, 7))

def _op5_qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & M32; x[c] = _rol32(x[c] ^ x[a], 15)
    x[d] = (x[d] + x[c]) & M32; x[b] = _rol32(x[b] ^ x[d], 11)
    x[a] = (x[a] + x[b]) & M32; x[c] = _rol32(x[c] ^ x[a], 9)
    x[d] = (x[d] + x[c]) & M32; x[b] = _rol32(x[b] ^ x[d], 6)

def op5_keystream_block(key44, counter):
    kw = struct.unpack("<8I", key44[:32])
    n0, n1, n2 = struct.unpack("<3I", key44[32:44])
    x = [0x6967416D, kw[0], kw[1], kw[2], kw[3],
         0x48432063, kw[4], kw[5], kw[6], kw[7],
         0x61684341, n0, n1, counter & M32, 0x754F5220, n2]
    init = x[:]
    for _ in range(10):
        for a, b, c, d in _COLS:
            _op5_qr(x, a, b, c, d)
        for a, b, c, d in _DIAGS:
            _op5_qr(x, a, b, c, d)
    # NEON ST4 输出: 字序 = [A0..A3, B0..B3, C0..C3, D0..D3] (行主序), 每字 LE
    # 其中 A=(x0,x5,x10,x14) B=(x1..x4) C=(x6..x9) D=(x13,x11,x12,x15)
    out = bytearray()
    for grp_idx, idxs in enumerate([(0, 5, 10, 14), (1, 2, 3, 4),
                                    (6, 7, 8, 9), (13, 11, 12, 15)]):
        for idx in idxs:
            out += ((x[idx] + init[idx]) & M32).to_bytes(4, "little")
    return bytes(out)

def op5(key44, data):
    out = bytearray(len(data))
    ctr = 1
    for off in range(0, len(data), 64):
        ks = op5_keystream_block(key44, ctr)
        ctr += 1
        n = min(64, len(data) - off)
        for i in range(n):
            out[off + i] = data[off + i] ^ ks[i]
    return bytes(out)

# ---------------------------------------------------------------- op6
# Blowfish, 初始 P/S 非 pi 常数:
#   P[18]  = 0x3130 起 18 个 u32 LE
#   S[1024]= 0x3178 起 1024 个 u32 LE (S0,S1,S2,S3 各 256)
_BF_PH = "fea419ace6d62830a2253da2cefce58c49c0a6764862b2586e8a482d58ad454d2364ba6cd2a4edd58422b326871c70a7202116455b4506c1a9c78d23f4a82b4a34c4146ad93294ce"
_BF_SH = "0e03a0444a4b730410da350cd2bd03fb4e159e6438db77eb92168d0a00041b44f1ddfce9074aa94fc3dbe0ff670a87edb62b336ce0512a749b38ecbbf78a66473b2c6d2f0a358d6ff431f6cc53c967d1ad4ea1d4b03986dbe9490d707bddecee1e260a0d7a27f6725b115b3834f005107ee049c6e456028149a25eac4636ae8fcff7d9f71ffcfe0194d1bd77fb27858dc50c922ca96de7adc9e210b75242ae1d8402e5960f5c7eb370a0b211f1b07d28132a2106fe518d89934d8e0d1ba80c776f0249f5bd811ddc0f4737a19066f4d4131a581e12300c0baa8111da9e004bb13b58234d7f1cc9759758dd196fe406d574c783d9d0a330be254c4ed18ffc5ed954b953f788472acc5a6dfdbcd7f053c8a0642546c1506efd8285c7dc0cbe8959e73bdded8525682fe94d96558f1a6669373ff94adcbce01c750ff99ed5a0093406f4875a2a93358f5654d53ea05be028a6711bad32a62c4f1665d134046a5f20d612774d51728f32ecac5e517e859aefad98e3f6eea45ea276ffc7b692cafe4bf7ed9e652eae1616703e54f08a0be7f56355e2401793ced4bbe4d7d957ccba9b6c134ba51fa345d6f9d14adee340d27c651fb457538f7c7da32658dff6eaedf76dbd98c77b1ea889f82a8a151328dca02b90bc2dddd69c467ba28ddd0050f9da5391c221d4d63d383e1dbc6568119c5b2dde4d09560c25e1184e487dd955ff52c0d373ac330fc0a00ef2becc42b38e66da927f63b065f7b2ddaa0f3d98d19b4c0fbd5dd8df61181cc3e8c3e98492dcb1e5c0eb752d9ec05e6ea6ef819e1273717ebaa3dc409ffdcb2b562a6b643077950a76fcf75ccaa3efd76a7e794ed21ffdac8886fa9e6ac1fc48d274489c1606d62bf598be33fb608fef61a9ca1a17843277a540e68234dc6f53494a6a2cbb634285fb3a016abe6115f00f390cc32621f55286d9a02b8bb0bccac49d0be14cf4a5be283e45b4ca0f0ab6651b917b6797b1bb47fa8aa9c2294bb72fda95901b60243e4947f40fc9ee377b68113421b90bbf395fd56984d64e14c9dbc19f5b075b321199c4b3e39966582a8dfc224819cd8b78387c16c1b977dac2364ab608b59d5b0a6873cfd98a309e1c4cd75eeb2754ee76270989e019749d030ff73f5f5dbbceb056f7c449c24fa3713335ebbe7798d83285815717452d68759e97a379fd48de866c8e51a0104df6e3ec54ac228cd4482e8e815a1d6779e7997db0264748f8237ad12455cbedee8d989c230c29c961f7ae62e43fce9ad03246f18de3c1c42eca9b2b6289f621edc3b9771878593ba549dfe1580679ef569f347e2099a8eee83c1bd953ec9c001cff312e0f178fd28fc2bb735f39abd930ebfbd62e4491a98400372321fe6cf364ea5bd61e8b1ab0b93164996c4dc5b9b2c14096975e32e885dc69b5020455f0aee346abdd067cf7e2758d17137abcb18192baf47b9f2bd88be17b838d90fedf2199bdf5ce7418622ee939d932873af3520ed3d96dc44a0ac8fc9f6125bfb84a1961ee2cb21e24c3b141155943710cfcd8b9937eb35c491460dbebdc294a94d1ae681c56c15e89096c0b3d7ba7120b77f2afe24b498e1f0a5062ab8f67353d11c09ca02b4e7e6cc9c959688002a9bc0a6bef1a65974e5af099bf68baec75014d2a93e77a6cbf6af14be8539236aa472ac992d0e0948f25a14bcd72c7a87ea369cfdd7c0c149dd1b1ec512807f2f7783d45b36cd5cd2b1f1fe8750b4182d10af8d303f5bf0f222b6078f6fc7124139a124764a94e1ca0ca3dc294cdc81e1993d239a3fab9f3e3c0df6ed55819640c296abd73f008f4deede259c38fb344ea81296b88b924e3345614308699b4545de40a95edd5ef16d923a338e5778bdaeea02ed87af6d5254226fa4f926208e926e8e273554603356fea939f4c12f2d33a70057c4343b5ca2984326c22d0e9404917df717450e56a1843f127e3d2534725805900f144b1e51f580a34e7d87cae03ca68c3e13865d6732a268e2b0c7c3837555812630bf7f9afead5c3836c90563968f767f79ac08c1c606bb734e427603a909e348cdee4f32ae11bc5a0e9a8e6142e37b1ecb922cb5d3c0716ccd2798e8d0615bd2882e00ba6fd3fe1e0f888e5cf09d50b8d35010d7b1e7d02a2c411c1677c6a112858a130abd16fe5286b7344d94b77696ca4e1dc3334bdb24d8b55a90912cdd04d675b94d3ab02c7cb4117ee35d5db8b8902c7935edb890a515f57ffbf21f12c165785440130c6bcdedae9c2de648245946943f37b6f4076961392be0c945005823ed531eaf3279d543d03590b6273482052ce64e1d378c51f27890285d8341a1d7208f6bfd218173f35acb24ae70bf2851134e02058b0a863824643bb36686e7f58d646e793f4b7757f662c58aa058a06144d2832cf651c3bfb13e0c4e05042f110c7249d7ae77a3182f0def9c462195113484655793e8ab231f3ab24040c1073e667999c08e83ea1e950d8f8a2a79b9d1742f85b81d807a89c4d540f2f375fd66a7e403f462931fa927c3f09d71c5142765824494842c24bbb7f79d4fb5f59c3a6aba4e53d8ada4bc833de1e372ffd46cec52eedfb6ebc41f617829b3e50b3aee946d7a19725cfd33587a9ed4b35503883eb563047f7730fe58570444ee5c14f3217ff386330cbf4c3697ff05b77501ee4ff5c0bf963991664ab0418aca2d879dde77f7cf5f4fcff6c9f44614f319fa7d49cd4a7e3b63095b199b59b5f50763930a0059149f052e558847aecc935ee145733fefdbc0ab55e15c1004093c742edaeda113a757cd30933a82b2c4794b130184734eb6786332865eac65c84af012873e75ffb8e2b5256afdc20b1b6e7de07b1fee07df4159e88aa8548b756b36ba69794aff1d9c755b6a8946188f2982669db1ddf8ee96deef2460f858d9aa286aa905bd12f149d3c751d6c81e9be4b6050769548c6d81f9be8093d3b81708422624cb3eb1f2ed6fc830054215f0d3534edbff75e74f4d1880c68f2472610f2593a7d71fa17135e0b6d5e5f00f3dbd63716d9b0accba7eec7f8e82d30b2890f4f0535011a20c729e67735564be3c0a3938261c42a12d4e2cf5884f2275ddc11b313696d89eb8e23f60f0de982ced2abb4b82f20c7eefa207978cad265fbf27d7da53d6b28a62f2b9bbd6c11e791453fe963853c99a421a148367873e3b3c881e7955fd5266e3efcffb95e314e847389c0319c39ffdb00dab234c90c996b396c93e7ce44a59aefd18b0dee3b3a304050022ec5bff13d6c3b09508fa49dd0f1316e3bf9389f214e337e0ebeb4fe02f6e0297722ef64e62b31d220bc83fa8ccc6c37c67aa861d49cdf31868fdc5461a1da0a8271cd6fcc5e933d0c468f9f10b317ff5653ce595d3d47965bdd30a12eb9d56aa33f4f9cae7fb6a3fd184b642fac4fef5879616d4904d8c5867145c29672e31e32bb9f77509418d3d3236f1738a5096045700997883593c7138b7d157294c521497ee9f96207109d85244252586d8c33e077e367397fde524e623fc256ccaea4d01e322bb2e5b47848da601507f5c545a8d135ff522a1e03bc64fdb9f5c7a1b1719de76d0719a0d5e344c1b9b52dc9bee7d6d4e31baedccd220118c3a17e7aa38c295f37797e2f5d8ae574fe799c5b9f4458586b4606e2f13d0c9c6093692997e1fb8588b5482b2e811cce902b575f4f7598121d9fc7a37aa08ef103057aba7c7adbde5e41b7fc345246edbe5935d6bae4b0ce1bffa2b3b8212a1f9141d870cb4f45bf925f778f1738ac2c3b0f84a44e91b1ed8af0ac3e97f8b90de7ab3557c09b3c72995d09a818c23090e593961885e8a10e8edb26110fd7784d05832650ef60f18dae8a8a0e5e2bb035a53c9c98fc24add4235178fd7e19fcab4cce8c0187898767d2aeb7a5fbce8b56d4b398ac14ef3ad2cd9f2ee8be34e56746a76c128aa9288b24f5c1e60c28be097ade7213a87a731b413c08b4c303a9959048f32f33ea4e6e0147769e289590d25987edd882fe5bd8cb0f527ae541288b8477e32223d785e86e1a7c62acb2d56784253f73acee26224dcdd83bd907c147da848aa6c91eea452de2a1e8e07626195e92372207b2fbb0539dfa3d67071261178306519a849f4199a1fca37bf6517ae2220e65cb1917a6b301aa1a4b4eca359073447a68ba8de8de9e5e7dd594f85d6ac2c32f7f82e7b75c9b41d55d114291e410875243dae00a2cd0cac0478127025975d351f39a4ab54beb5ca223583694faca97f56ecdb362173cdf13d19e4080d48489043415ae229636dd288c8be85b14e2a156ef34654bf4ea832997bbf00615ed0522aa0baddec71f267f5220f7b1af7886f17597745014739e426eedd244943e55f9ff6847d5231ec66e399cb9b703127aa0bdbc9834d2ac70271ec2a8dfad9260ea6448d21b035852dcaa7c83897f015fc43c1e82b3868e19672782f937dd2ac17796c1bc5b9269c9bba69999738a8ae74843891952bb82882f0d7abbb9024133cb37a3b89defeec4ec6735f090745ec28a6c1615ead249ca5fd244ce5bb8ab853f1e84fc19ae28f39903a1f377800a616ef8333b33f2e48a07a48ff1b1179c5960669d4786e7dd67869b77de6f13dfaaf4e3863aa0dc61e830b86474f31d4f68de7c09fe9e875b97fc0b46ab8b6ff6a76732f419f4acdca9f1ec43c60e6805636e89081c46df9debce0ce6fdc66befb30375750704182d2067fc2d17c335f931eafc2c21bd8cdf3fb67e75b8ec565992af6f1d1c78a86db81353c89cdacf34fa3aa882c93f23aa89b804d49baabbf8ea116875d1f9862ffce3133bd92e6e3aeb7abc5c0be2276c5dd20b6f13ed30cfff4b956129c8af548ca466eb81228104032fd79249641a3c07bf754e5990b3194ad0d001cdb29664ed50fd5c5d725ea604856d85cb7a2e408da78be5783ae86ab10a0ef303e0339fdeb0c26d3800bd5e0678164dd113a09a8ebab0bb11d59e3f04c475f3bbf77f0ea77ba09b28ea823b3fc5d8962e12cc51ad853e9b410bb9c26dc85f00b3cf71ab2a79609744225e21c46da0d7da55fd3ae06369e33be8be3e7ca559a4279f3e9086ed1828e701a2dbc1da81c660b6919024c835fd7148cd4f35de4e85ed42fd3f10af1585bd0aa5c0c0cdce52ff7bab38fedcd612271a12d56dee90cd9d9a8c0134a0ba4a8928308edb340d9cc7bc183b54c98f59a0f538a1b5ea7d3433675a76c94da6cfdbfd68251788840f183ebe4bf02b81abf10e38147ef9f7e4689cd63d6b91a32b39259fda0012a18d8beaeb6a4a82705d86be4e0e000ea81bfc140434bd4b6d4e17bdefb2a3016051ab9e9e2313f6741695210b4dff111d1a1feb5fe84f656c9879ad95067446afbc1a4af20b71f7cf253df0814cc9326f9c6a421744c3e0f5af0a675f1df4e78a5cf4a3310b8650d155436641fb35112342b62815b493e40ae50cfe0e32974ece628381d872a76323d997e0262b8027d2c4cc7e41dd0cb28530528440b49cee6e09532f6e1a5cc4275136ec74ef62b85ba62f364ab620e78fd47cb3e5be13b2652eeb1864de5461b0df5c4ff0ce5d8c91f2019f267949fa2f82f8ccbdda2e08b4d010e39217919592a723b342746629b6b8bf647b6b759ad6ebb4b6b0c48d74f365e224cf7e3cc841d3d018f2901528aae2e1daa4d5fe9999611e94a80da90026243f2c87f7f29075e00e9c90e2337983efb3badf50a17b9caaf2cddb1737329cacb6571cd724bab5a6a448a531956048f25acb08f907932f55a2f4619f990b5034a56a0ad98061fe35"
_BF_P = [int(_BF_PH[i:i + 8], 16) for i in range(0, len(_BF_PH), 8)]
_BF_S = [int(_BF_SH[i:i + 8], 16) for i in range(0, len(_BF_SH), 8)]

def _bf_f(S, x):
    return (((S[x >> 24] + S[256 + ((x >> 16) & 0xFF)]) & M32)
            ^ S[512 + ((x >> 8) & 0xFF)]) + S[768 + (x & 0xFF)] & M32

def _bf_enc16(ctx, xl, xr):
    # 16 轮, 轮密钥取 ctx[i] (扁平数组, 见 _bf_schedule), F 用 ctx[18..] 的 S 区
    for i in range(16):
        t = ctx[i] ^ xl
        xl = _bf_f(ctx[18:], t) ^ xr
        xr = t
    return xl, xr

def _bf_schedule(key):
    """0x22D58。注意: P 与 S 同住一个 1042 字的扁平数组:
    ctx[0..17] = 初始 P(0x3130) ^ key 字; ctx[18..1041] = 初始 S(0x3178)。
    轮密钥/盒子都从这个数组现读, 生成对依次覆写 ctx[0..17] (9 对) 再
    覆写 S 区 (4x128 对, 基址 18/274/530/786)。存对 = (ctx[17]^xr, ctx[16]^xl)。
    """
    ctx = [0] * 1042
    L = len(key)
    c = 0
    for i in range(18):
        w = (key[c % L] << 24) | (key[(c + 1) % L] << 16) |             (key[(c + 2) % L] << 8) | key[(c + 3) % L]
        ctx[i] = _BF_P[i] ^ w
        c = (c + 4) % L
    for i in range(1024):
        ctx[18 + i] = _BF_S[i]
    xl = xr = 0
    for k in range(9):                       # 覆写 P[0..17]
        xl, xr = _bf_enc16(ctx, xl, xr)
        ctx[2 * k], ctx[2 * k + 1] = (ctx[17] ^ xr) & M32, (ctx[16] ^ xl) & M32
        xl, xr = ctx[2 * k], ctx[2 * k + 1]
    for base in (18, 274, 530, 786):         # 覆写 S0..S3
        for k in range(128):
            xl, xr = _bf_enc16(ctx, xl, xr)
            ctx[base + 2 * k], ctx[base + 2 * k + 1] = (ctx[17] ^ xr) & M32, (ctx[16] ^ xl) & M32
            xl, xr = ctx[base + 2 * k], ctx[base + 2 * k + 1]
    return ctx

def _bf_enc_block(ctx, block):
    xl = int.from_bytes(block[0:4], "big")
    xr = int.from_bytes(block[4:8], "big")
    xl, xr = _bf_enc16(ctx, xl, xr)
    # 0x10634/0x10658: 字1 = xl16 ^ ctx[17], 字2 = xr16 ^ ctx[16]
    return ((xr ^ ctx[17]) & M32).to_bytes(4, "big") +            ((xl ^ ctx[16]) & M32).to_bytes(4, "big")

def _bf_dec_block(ctx, block):
    # bf_full 0x123B8: 16 轮 P[17..2] 降序, 字1 = ctx[0]^R16, 字2 = ctx[1]^L16
    L = int.from_bytes(block[0:4], "big")
    R = int.from_bytes(block[4:8], "big")
    for i in range(17, 1, -1):
        t = ctx[i] ^ L
        L = _bf_f(ctx[18:], t) ^ R
        R = t
    return ((ctx[0] ^ R) & M32).to_bytes(4, "big") +            ((ctx[1] ^ L) & M32).to_bytes(4, "big")

def op6_enc(key, data):
    ctx = _bf_schedule(key)
    padded = _pad8(data)
    return b"".join(_bf_enc_block(ctx, padded[i:i + 8])
                    for i in range(0, len(padded), 8))

def op6_dec(key, data):
    if len(data) == 0 or len(data) & 7:
        raise ValueError("op6_dec: bad length")
    ctx = _bf_schedule(key)
    return _unpad(b"".join(_bf_dec_block(ctx, data[i:i + 8])
                           for i in range(0, len(data), 8)), "op6")

# ---------------------------------------------------------------- 分发器
_KEYLEN = {1: 8, 2: 16, 3: 0, 4: 16, 5: 44, 6: 16}

def mc_process(opcode, key, data, enc, directory=None):
    """zqmc_mc_process @0x0EEAC。返回转换后的数据。"""
    op = opcode & 0xFF
    if op < 1 or op > 6:
        raise ValueError("mc_process: bad opcode %d" % opcode)
    need = _KEYLEN[op]
    if need and len(key) != need:
        raise ValueError("mc_process: op%d needs keyLen %d, got %d"
                         % (op, need, len(key)))
    if op == 1:
        return op1_enc(key, data) if enc else op1_dec(key, data)
    if op == 2:
        return op2(key, data)
    if op == 3:
        return op3_enc(data) if enc else op3_dec(data)
    if op == 4:
        return op4_enc(key, data) if enc else op4_dec(key, data)
    if op == 5:
        return op5(key, data)
    return op6_enc(key, data) if enc else op6_dec(key, data)

_DEFAULT_DIR = {i: i for i in range(1, 7)}

def _dir_of(directory):
    return directory if directory else _DEFAULT_DIR

# ---------------------------------------------------------------- 链/容器
def encode_chunk(segments, payload, directory=None):
    """native 0x249C4: 对单个块按段序做 opcode 链加密。"""
    d = _dir_of(directory)
    buf = bytes(payload)
    for sid, key in segments:
        if sid not in d:
            raise ValueError("encode_chunk: id %r not in directory" % (sid,))
        buf = mc_process(d[sid], key, buf, 1)
    return buf

def decode_chunk(segments, blob, directory=None):
    """native 0x25940: 逆序 opcode 链解密。"""
    d = _dir_of(directory)
    buf = bytes(blob)
    for sid, key in reversed(segments):
        if sid not in d:
            raise ValueError("decode_chunk: id %r not in directory" % (sid,))
        buf = mc_process(d[sid], key, buf, 0)
    return buf

def build_container(payload, chunk_encoder):
    """encrypt_v3 分块路径 (0x19448..): >64KB 明文 -> "ECSM" 容器."""
    n = len(payload)
    count = (n + CHUNK - 1) // CHUNK
    out = bytearray(b"ECSM\x00\x01\x00\x00")
    out += (count & M32).to_bytes(4, "big")
    for i in range(count):
        piece = payload[i * CHUNK:(i + 1) * CHUNK]
        enc = chunk_encoder(piece)
        out += len(enc).to_bytes(4, "big")
        out += enc
    return bytes(out)

def parse_container(container, chunk_decoder):
    """native 0x25088: 解析 "ECSM" 容器并逐块解码。"""
    if len(container) < 12 or container[:4] != b"ECSM":
        raise ValueError("parse_container: bad magic")
    count = int.from_bytes(container[8:12], "big")
    pos = 12
    out = bytearray()
    for _ in range(count):
        if pos + 4 > len(container):
            raise ValueError("parse_container: truncated")
        ln = int.from_bytes(container[pos:pos + 4], "big")
        pos += 4
        if pos + ln > len(container):
            raise ValueError("parse_container: chunk overflow")
        out += chunk_decoder(container[pos:pos + ln])
        pos += ln
    return bytes(out)

def encode(segments, payload, directory=None):
    """encrypt_v3 分块语义: <=64KB 单块; >64KB "ECSM" 容器。"""
    payload = bytes(payload)
    if len(payload) <= CHUNK:
        return encode_chunk(segments, payload, directory)
    return build_container(
        payload, lambda piece: encode_chunk(segments, piece, directory))

def decode(segments, blob, directory=None):
    """native 0x25088/0x25940 双路径; 以 "ECSM" 魔数自动识别。"""
    blob = bytes(blob)
    if blob[:4] == b"ECSM" and len(blob) >= 12:
        return parse_container(
            blob, lambda piece: decode_chunk(segments, piece, directory))
    return decode_chunk(segments, blob, directory)

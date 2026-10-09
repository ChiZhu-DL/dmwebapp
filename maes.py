"""
maes (MagicFingerprintLib.maesProcess / mbase64 底层块加密) — 还原自 libmagic_cipher.so

加密 maes_enc @0x1FA64（maes_dec @0x20220 为其逆；JNI 入口 @0xA478/0x1F6C0 分发）:
  1) PKCS7 填充: pad = 16 - (len % 15 & 0xF) 实为 16-(len & 0xF)，len 为 16 倍数时补 16
  2) AES-CBC（AES-128，key=16B，iv=16B）: c_i = AES_E(p_i XOR c_{i-1})
  3) 魔改 RC4 覆盖层（作用于 CBC 密文，逐字节流，与数据无关 → 解密同一 keystream 异或即可）:
     - K[256] = key[i & 15]（16B 密钥重复 16 次作为 RC4 密钥表）
     - S[256] 初始化为 AES S-box 常量表（so 内 0x44FC..0x45FC，256B，即标准 AES S-box）
     - KSA: j=0; for i in 0..255:
           j = (j + S[i] + K[i]) & 0xFF
           t = S[i]; S[i] = S[j]; S[j] = t ^ 0x66     # 魔改点 1: 交换时第二槽 XOR 0x66
     - PRGA: i=0, j=0; for idx in 0..n-1:
           i = (i + 1) & 0xFF
           j = (j + S[i]) & 0xFF
           swap(S[i], S[j])
           ks = S[(S[i] + S[j]) & 0xFF]
           out[idx] = cbc_out[idx] ^ ks ^ ((idx + 52) & 0xFF)   # 魔改点 2: 位置相关异或 (idx+52)

解密: 先用同一 keystream 异或（自反），再 AES-CBC 解密，去 PKCS7。

置信度：结构逐条对照 0x1FA64 反汇编（KSA/PRGA/常量表/XOR 常量均已核实）；
AES 轮函数 off_2A468/密钥扩展 off_2A458 视为标准 AES-128（未逐轮核对，置信度中高）。
"""
from Crypto.Cipher import AES

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
assert len(AES_SBOX) == 256


def _mrc4_keystream(key: bytes, n: int) -> bytes:
    """魔改 RC4 keystream（含位置异或 (idx+52)）。"""
    k = bytes(key[i % len(key)] for i in range(256))
    s = bytearray(AES_SBOX)
    j = 0
    for i in range(256):
        j = (j + s[i] + k[i]) & 0xFF
        t = s[i]
        s[i] = s[j]
        s[j] = t ^ 0x66
    out = bytearray(n)
    i = j = 0
    for idx in range(n):
        i = (i + 1) & 0xFF
        sj = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        j = sj
        ks = s[(s[i] + s[j]) & 0xFF]
        out[idx] = ks ^ ((idx + 52) & 0xFF)
    return bytes(out)


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) & 0xF)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def maes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """key/iv 均 16B；等价 native maesProcess(data, key, iv, encrypt=true) 的块级逻辑。"""
    padded = _pkcs7_pad(data)
    cbc = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
    ks = _mrc4_keystream(key, len(cbc))
    return bytes(a ^ b for a, b in zip(cbc, ks))


def maes_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    ks = _mrc4_keystream(key, len(data))
    cbc = bytes(a ^ b for a, b in zip(data, ks))
    return _pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cbc))

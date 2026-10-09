"""
bootstrap 密钥派生与 BootstrapConfig 解密 — 还原自 libmagic_cipher.so (arm64)
已用 HAR 中真实 bootstrap.jpg (2026-09-19, _t=1789820952657) 验证通过。

调用链（IDA）:
  Java_..._MagicFingerprintLib_nativeBootstrapDeriveCandidateKeys  @0xAC4C
    -> magic_sdk_derive_bootstrap_candidate_keys @0x1654C（月轮换: t/2592000，分别派生 月-1/月/月+1）
    -> sub_1694C @0x1694C（单月派生）
    -> sub_14A64 @0x14A64 = HMAC-SHA512(key=32B, msg)（128B 分组、0x36/0x5C pad、64B 输出）

算法:
  month      = unixSec // 2592000            (30 天轮换)
  key32      = (payload0||payload1) XOR M1  ||  (payload2||payload3) XOR M2
  candidate  = HMAC-SHA512(key32, "bootstrap:" + appId + ":" + str(month))   # 64B
  candidate[0:32]  = AES-256-CBC 密钥
  candidate[32:64] = HMAC-SHA256 完整性密钥

BootstrapConfig 载荷（dex R3.C3731o + JPEG EOI 之后）:
  magic 4B = 89 50 43 47 ("\x89PCG") | payloadLen u32 BE | IV 16B | ct payloadLen | tag 32B
  tag  == HMAC-SHA256(candidate[32:64], IV||ct)
  json == AES-256-CBC/PKCS7(candidate[0:32], IV).decrypt(ct)

版本号 (0x17508): version = ((b0^0x9B)<<24)|((b1^0x53)<<16)|((b2^0x8B)<<8)|(b3^0x48)
"""
import hashlib
import hmac
import json

# u3.C4320c / D4.e 配置常量（api.appconfig.payload*）
PAYLOAD0 = bytes.fromhex("3a881c742789416a")
PAYLOAD1 = bytes.fromhex("997ade9f1b84679a")
PAYLOAD2 = bytes.fromhex("60b97b4906521e31")
PAYLOAD3 = bytes.fromhex("859a046e3fe1b4ab")
PAYLOAD_V = bytes.fromhex("9b538b49")  # -> keyVersion 1
APP_ID = "315891530526580736"

# 0x1694C 内 XOR 掩码（xmmword_3070 / xmmword_30E0）
MASK1 = bytes.fromhex("21caab4890ce93bbb7a4231991fff4dd")
MASK2 = bytes.fromhex("b434ed91730345e330f13b6a3c670fbf")

INFO_PREFIX = b"bootstrap:"  # 0x278EC 字符串解密器: dst[i]=src[26+i]^src[i%26], 源 unk_4B4C@0x4B4C
MONTH_SECONDS = 2592000  # 30 天
MAGIC = b"\x89PCG"


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def derive_candidate_key(payload0: bytes, payload1: bytes, payload2: bytes, payload3: bytes,
                         app_id: str, unix_sec: int, month: int = None) -> bytes:
    """单月候选密钥 (64B)。month 缺省由 unix_sec 推。"""
    if month is None:
        month = unix_sec // MONTH_SECONDS
    key32 = xor(payload0 + payload1, MASK1) + xor(payload2 + payload3, MASK2)
    info = INFO_PREFIX + app_id.encode() + b":" + str(month).encode()
    return hmac.new(key32, info, hashlib.sha512).digest()


def derive_candidate_keys(app_id: str = APP_ID, unix_sec: int = 1789820952,
                          p0=PAYLOAD0, p1=PAYLOAD1, p2=PAYLOAD2, p3=PAYLOAD3):
    """nativeBootstrapDeriveCandidateKeys 的 192B 输出: [prev, current, next] 各 64B。"""
    month = unix_sec // MONTH_SECONDS
    return [derive_candidate_key(p0, p1, p2, p3, app_id, unix_sec, month - 1),
            derive_candidate_key(p0, p1, p2, p3, app_id, unix_sec, month),
            derive_candidate_key(p0, p1, p2, p3, app_id, unix_sec, month + 1)]


def assemble_bootstrap_version(payload_v: bytes = PAYLOAD_V) -> int:
    b = payload_v
    return ((b[0] ^ 0x9B) << 24) | ((b[1] ^ 0x53) << 16) | ((b[2] ^ 0x8B) << 8) | (b[3] ^ 0x48)


def parse_jpeg_tail(image: bytes):
    """JPEG EOI(FFD9) 之后: magic4 | payloadLen u32BE | iv16 | ct(len) | tag32"""
    eoi = image.rfind(b"\xff\xd9")
    if eoi < 0:
        raise ValueError("不是有效的 JPEG 图片（未找到 EOI FF D9）")
    tail = image[eoi + 2:]
    if len(tail) < 56 or tail[:4] != MAGIC:
        raise ValueError("无效的隐写标记（magic 不匹配）")
    payload_len = int.from_bytes(tail[4:8], "big")
    if payload_len <= 0 or len(tail) < payload_len + 56:
        raise ValueError(f"载荷数据不完整（payloadLen={payload_len}, tail={len(tail)}）")
    iv = tail[8:24]
    ct = tail[24:24 + payload_len]
    tag = tail[24 + payload_len:56 + payload_len]
    return iv, ct, tag


def _pkcs7_unpad(data: bytes) -> bytes:
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 padding 无效")
    return data[:-n]


def decrypt_bootstrap_config(image: bytes, candidates=None, unix_sec: int = None,
                             app_id: str = APP_ID):
    """JPEG bytes -> (config dict, 中间值 dict)。纯 Python（AES 走 pycryptodome，可换 cryptography）。"""
    from Crypto.Cipher import AES
    iv, ct, tag = parse_jpeg_tail(image)
    if candidates is None:
        candidates = derive_candidate_keys(app_id=app_id, unix_sec=unix_sec or 0)
    matched = None
    for cand in candidates:
        calc = hmac.new(cand[32:64], iv + ct, hashlib.sha256).digest()
        if hmac.compare_digest(calc, tag):
            matched = cand
            break
    if matched is None:
        raise ValueError("HMAC 校验失败 — 全部候选密钥都不匹配")
    pt = _pkcs7_unpad(AES.new(matched[:32], AES.MODE_CBC, iv).decrypt(ct))
    return json.loads(pt.decode("utf-8")), {
        "iv": iv.hex(), "ct_len": len(ct), "tag": tag.hex(),
        "candidate_hex": matched.hex(),
        "aes_key": matched[:32].hex(), "hmac_key": matched[32:].hex(),
    }


def master_key(master_secret: str, device_id: str) -> str:
    """v3 报文主密钥: hex(HMAC-SHA256(utf8(masterSecret), utf8('device:'+deviceID))) 64 hex chars"""
    return hmac.new(master_secret.encode(), ("device:" + device_id).encode(),
                    hashlib.sha256).hexdigest()


if __name__ == "__main__":
    import sys
    img = open(sys.argv[1] if len(sys.argv) > 1 else "bootstrap.jpg", "rb").read()
    ts = int(sys.argv[2]) if len(sys.argv) > 2 else 1789820952
    cfg, mid = decrypt_bootstrap_config(img, unix_sec=ts)
    print("version =", assemble_bootstrap_version())
    print("masterSecret =", cfg.get("masterSecret"))
    print(json.dumps(cfg, ensure_ascii=False, indent=2))
    print("candidate =", mid["candidate_hex"])

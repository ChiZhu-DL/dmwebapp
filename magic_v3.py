# -*- coding: utf-8 -*-
"""magic_v3 —— libmagic_cipher.so v3 帧协议的完整、已验证 Python 实现。

★ 2026-09-20 全链路打通：native(Unicorn) 与线上真实帧逐字节一致。

协议全貌
--------
masterSecret(32 hex)  ──bootstrap.jpg(AES-256-CBC)──►  7b94a2ab809388c89cdee6751701e638
deviceId(64 hex)      = hex(SHA-256(deviceId material 多行串)) = x-device-id 头
masterKey  MK(64B)    = utf8_hex( HMAC-SHA256(utf8(masterSecret), utf8("device:"+deviceId)) )

帧:
  [0]      0x03                          版本
  [1]      multiFlag                     明文 > 64KiB 时 1（blob 为 "ECSM" 容器）
  [2..10]  slot        u64 BE = sec//3600
  [10]     kmLen = 1 + segCount
  [11]     segCount                      ← 未掩码
  [12..]   masked ids   ids[i] ^ ks[i-1] ← 掩码后
  [..+2]   segTotal     u16 BE           段表总字节数
  [..]     segTable     [u16 keylen][key] × segCount
  [..]     blob                          ≤64KiB 单块链密文；否则 "ECSM" 容器
  [尾]     tag 32B      HMAC-SHA256(MK, IV2 ‖ body)

  ks  = HMAC-SHA256(MK, slot_BE8 ‖ IV1)      IV1 = b"wire-code-mask"   (槽位15)
  IV2 = b"payload-integrity"                 (槽位16)

★ 关键点（此前卡住的地方）：目录里的段 id 是「混淆 id」，不是 1..6：
      wire_id   opcode   算法              keyLen
        0x19      2      MagicRC4            16
        0x3b      5      MagicChaCha20       44
        0x75      6      MagicBlowfish       16
        0x82      3      MagicBase64          0
        0x9a      4      MagicTEA            16
        0xe4      1      MagicXOR             8
"""
import hashlib
import hmac
import os

import ecsm

VERSION = 3
IV1 = b"wire-code-mask"       # 槽位 15 → magic_sdk_derive_wire_mask 的 msg 尾
IV2 = b"payload-integrity"    # 槽位 16 → tag 的 msg 前缀
TAG_LEN = 32
CHUNK = 0x10000

#: (wire_id, opcode, key_len) —— 顺序 = App 传给 magic_sdk_init 的目录顺序
CATALOG = [
    (0x19, 2, 16),   # MagicRC4
    (0x3b, 5, 44),   # MagicChaCha20
    (0x75, 6, 16),   # MagicBlowfish
    (0x82, 3, 0),    # MagicBase64
    (0x9a, 4, 16),   # MagicTEA
    (0xe4, 1, 8),    # MagicXOR
]
DIRECTORY = {wid: op for wid, op, _ in CATALOG}
KEYLEN = {wid: ln for wid, _, ln in CATALOG}

#: App 在 mode=0（业务请求）下实际使用的段链（wire id 序）
DEFAULT_CHAIN = (0xE4, 0x82, 0xE4, 0x19)


# --------------------------------------------------------------- 密钥
def master_key(master_secret: str, device_id: str) -> bytes:
    """masterSecret + deviceId(64hex) → 64 字节 ASCII hex 主密钥。"""
    return hmac.new(master_secret.encode(), ("device:" + device_id).encode(),
                    hashlib.sha256).hexdigest().encode()


def wire_mask(mk: bytes, slot: int) -> bytes:
    """magic_sdk_derive_wire_mask：HMAC-SHA256(MK, slot_BE8 ‖ IV1)。"""
    return hmac.new(mk, slot.to_bytes(8, "big") + IV1, hashlib.sha256).digest()


def slot_of(ts_sec: int) -> int:
    """magic_sdk_slot_from_time。"""
    return ts_sec // 3600


def tag_of(mk: bytes, body: bytes) -> bytes:
    return hmac.new(mk, IV2 + body, hashlib.sha256).digest()


# --------------------------------------------------------------- 组帧
def build_frame(mk: bytes, wire_ids, seg_keys, blob: bytes, slot: int,
                multi: int = 0) -> bytes:
    n = len(wire_ids)
    assert len(seg_keys) == n
    ks = wire_mask(mk, slot)
    masked = bytes(wid ^ ks[i] for i, wid in enumerate(wire_ids))
    table = b"".join(len(k).to_bytes(2, "big") + k for k in seg_keys)
    body = (bytes([VERSION, multi])
            + slot.to_bytes(8, "big")
            + bytes([1 + n, n]) + masked
            + len(table).to_bytes(2, "big") + table + blob)
    return body + tag_of(mk, body)


def parse_frame(frame: bytes, mk: bytes, verify: bool = True) -> dict:
    assert frame[0] == VERSION, f"版本非 3: {frame[0]}"
    body, tag = frame[:-TAG_LEN], frame[-TAG_LEN:]
    if verify and not hmac.compare_digest(tag_of(mk, body), tag):
        raise ValueError("tag 校验失败")
    multi = frame[1]
    slot = int.from_bytes(frame[2:10], "big")
    km_len, seg_count = frame[10], frame[11]
    assert km_len == seg_count + 1, f"kmLen {km_len} != 1+{seg_count}"
    ks = wire_mask(mk, slot)
    wire_ids = [frame[12 + i] ^ ks[i] for i in range(seg_count)]
    p = 12 + seg_count
    seg_total = int.from_bytes(body[p:p + 2], "big")
    p += 2
    seg_keys, pos = [], 0
    while pos < seg_total:
        ln = int.from_bytes(body[p + pos:p + pos + 2], "big")
        seg_keys.append(body[p + pos + 2:p + pos + 2 + ln])
        pos += 2 + ln
    assert pos == seg_total, "段表未闭合"
    assert [len(k) for k in seg_keys] == [KEYLEN[w] for w in wire_ids], "段长与 id 不符"
    return {"multi": multi, "slot": slot, "seg_count": seg_count, "wire_ids": wire_ids,
            "opcodes": [DIRECTORY[w] for w in wire_ids], "seg_keys": seg_keys,
            "blob": body[p + seg_total:], "tag": tag, "body": body}


def unpack(frame: bytes, mk: bytes) -> bytes:
    """帧 → 明文。"""
    f = parse_frame(frame, mk)
    return ecsm.decode(list(zip(f["wire_ids"], f["seg_keys"])), f["blob"], DIRECTORY)


def pack(mk: bytes, plaintext: bytes, slot: int, chain=DEFAULT_CHAIN,
         seg_keys=None) -> bytes:
    """明文 → 帧。chain = wire id 序（默认与 App 请求一致）。"""
    plaintext = bytes(plaintext)
    keys = seg_keys or [os.urandom(KEYLEN[w]) for w in chain]
    blob = ecsm.encode(list(zip(chain, keys)), plaintext, DIRECTORY)
    return build_frame(mk, chain, keys, blob, slot,
                       multi=1 if len(plaintext) > CHUNK else 0)


if __name__ == "__main__":
    import json
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    MS = "7b94a2ab809388c89cdee6751701e638"
    DID = "29e440fdbde89e944e143434b2494f1c6cc1befab90feeb87c193e82f07df6e1"
    mk = master_key(MS, DID)
    print("MK =", mk.decode())
    pt = b'{"videoId":"318186697634738205","code":"cn","episodeNum":157}'
    fr = pack(mk, pt, slot_of(1789837200))
    print("pack 帧长:", len(fr), "| km:", fr[12:16].hex())
    assert unpack(fr, mk) == pt, "往返失败"
    print("往返自测 OK")

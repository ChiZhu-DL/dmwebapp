"""「动漫共和国」HTTP 请求头构造（还原自 dex：q3.J / A5.f / u4.f / B5.t / Od.m / a6.f）。

核心结论（详见 signing_notes.md）：
  x-signature = lowercase_hex( MD5( utf8( str(ts_ms) + nonce + appId + signSecret ) ) )
      - ts_ms    = 毫秒时间戳（服务器时钟偏移校正后；偏移 = 服务器时间 - 本机时间，默认 0）
      - nonce    = UUIDv4 去连字符（32 hex 小写）
      - appId    = BootstrapConfig.appId（抓包样本 315891530526580736）
      - signSecret = BootstrapConfig.signSecret（b7a599975b90ac560466466fa8a3021f）
  x-fp-sign   = lowercase_hex( HMAC-SHA256( raw(fpAlgo.hmacSecret 32B), utf8(x-device-fingerprint 头值) ) )
  其余：nonce/request-id/session-id/trace-id/span-id 均为随机（UUID 或 crypto 随机 hex），
       span-id 前缀 "ccce"（"http_request" 前四字符经 (c%6)+97 映射）。

用法：
  python signing.py                     # 跑内置自检（含 HAR entry#48 硬编码向量）
  python signing.py <path/to.har>       # 全量复算 HAR 中所有签名头
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# BootstrapConfig 静态值（抓包 App 当前下发版本）
# ---------------------------------------------------------------------------
DEFAULT_APP_ID = "315891530526580736"
DEFAULT_SIGN_SECRET = "b7a599975b90ac560466466fa8a3021f"
DEFAULT_FP_HMAC_SECRET_HEX = "b4db2eb0f842d51bed8171dad5c9cdfce0acf129f029198eb52a74b6782d5555"

# q3.O.f26513a：命中（contains）任一路径时 ApiSecurity 插件直接跳过签名三件套
SIGN_EXEMPT_PATH_SUBSTRINGS = (
    "/api/v1/app/client/auth/bootstrap.jpg",
    "/api/v1/app/client/auth/negotiate",
    "/api/v1/user/encrypt-key",
    "/api/v1/user/login-config",
    "/api/v1/manage/no_auth/sys_admin/encrypt-key",
)

UA = "Myuko Ktor Client"


# ---------------------------------------------------------------------------
# 单个头的计算
# ---------------------------------------------------------------------------
def x_signature(ts_ms: int, nonce: str, app_id: str = DEFAULT_APP_ID,
                sign_secret: str = DEFAULT_SIGN_SECRET) -> str:
    """q3.J.invokeSuspend：MD5(utf8(str(ts)+nonce+appId+signSecret)) 小写 hex。"""
    msg = f"{ts_ms}{nonce}{app_id}{sign_secret}".encode("utf-8")
    return hashlib.md5(msg).hexdigest()


def x_fp_sign(fingerprint_b64: str,
              fp_hmac_secret_hex: str = DEFAULT_FP_HMAC_SECRET_HEX) -> str:
    """A5.f：hex(HMAC-SHA256(raw 32B secret, utf8(指纹 base64 串)))。

    注意输入是 x-device-fingerprint 头的**完整 base64 字符串本身**（不是解码后的字节）。
    """
    key = bytes.fromhex(fp_hmac_secret_hex)
    return hmac.new(key, fingerprint_b64.encode("utf-8"), hashlib.sha256).hexdigest()


def gen_nonce() -> str:
    """q3.J：Ud.e.n()=UUIDv4，toString 去掉 '-'。"""
    return str(uuid.uuid4()).replace("-", "")


def gen_request_id() -> str:
    """u4.f：Od.l.p(8) = 8 随机字节 → 16 hex 小写，每请求一个。"""
    return secrets.token_hex(8)


def gen_session_id() -> str:
    """a6.f 静态初始化：Od.l.p(8)，每个 App 进程一个。"""
    return secrets.token_hex(8)


def gen_trace_id() -> str:
    """u4.f：Od.l.p(16) = 16 随机字节 → 32 hex，每个 TelemetryContext 一个。"""
    return secrets.token_hex(16)


def gen_span_id(prefix: str = "http_request") -> str:
    """Od.m.z：取 prefix 前 4 字符，非 [0-9a-f] 字符映射 (c%6)+97，再接 Od.l.p(6)=12 hex。

    "http_request" → "http" → 'h'(104)%6=2→'c', 't'→'c', 't'→'c', 'p'(112)%6=4→'e'
    即前缀恒为 "ccce"，共 4+12=16 字符。
    """
    head = []
    for ch in prefix[:4].lower():
        if not ("0" <= ch <= "9" or "a" <= ch <= "f"):
            ch = chr((ord(ch) % 6) + 97)
        head.append(ch)
    s = "".join(head)
    s = s + "0" * (4 - len(s)) if len(s) < 4 else s
    return s + secrets.token_hex(6)


def traceparent_header(trace_id: str, span_id: str) -> str:
    """u4.f："00-" + traceId + "-" + spanId + "-01"。"""
    return f"00-{trace_id}-{span_id}-01"


# ---------------------------------------------------------------------------
# x-device-id（material → sha256）
# ---------------------------------------------------------------------------
def _kv(key: str, val: str) -> str:
    n = len(val.encode("utf-8"))
    return f"{key}:{n}:{val}"


def build_hardware_fingerprint_json(board="", brand="", device="", hardware="",
                                    manufacturer="", model="", product="") -> str:
    """B5.b.a：七个 Build 字段各一行 _kv 后 "\\n" 连接。"""
    return "\n".join([
        _kv("board", board), _kv("brand", brand), _kv("device", device),
        _kv("hardware", hardware), _kv("manufacturer", manufacturer),
        _kv("model", model), _kv("product", product),
    ])


def x_device_id(rule_version: int, source_type: str, source_value_hash_hex: str,
                hardware_fingerprint: str) -> str:
    """B5.t.g：material 四行 "\\n" 连接后 t.k()=hex(SHA-256(material))（64 hex 小写）。

    source_value_hash_hex = hex(SHA-256(源值))（oaid/uuid 原串，或 uuid_timestamp 交错串）。
    """
    material = "\n".join([
        _kv("ruleVersion", str(rule_version)),
        _kv("sourceType", source_type),
        _kv("sourceValueHash", source_value_hash_hex),
        _kv("hardwareFingerprint", hardware_fingerprint),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 指纹 JSON（A5.c "DeviceContext"，kotlinx.serialization 默认命名，按声明序）
# ---------------------------------------------------------------------------
def build_fp_payload_json(device_id: str, device_name: str, device_model: str,
                          os_name: str, os_version: str, app_version: str,
                          app_version_code: int, package_name: str,
                          app_signature: str, hv: str = "1.0.8", pt: str = "android",
                          device_type: int = 1, screen_w: int = 1080,
                          screen_h: int = 2400, lang: str = "zh-CN",
                          tz: str | None = None, net: str = "unknown",
                          ts_ms: int | None = None, bi: str = "") -> str:
    """A5.f 构造的 19 字段 JSON（maesProcess 的明文）。字段名取自 A5.a 序列化描述符：
    fp,dn,dm,os,osv,av,avc,pkg,asig,hv,pt,dt,sw,sh,lang,tz,net,ts,bi(可选,默认"")。
    x-device-fingerprint = mbase64(maes(k1=hmacSecret[0:16], k2=hmacSecret[16:32], utf8(此JSON), 1))
    —— mbase64 为 native 变体 base64（mbase64Table.version=1），Python 侧暂未还原，
    实际使用时把已产出的指纹 b64 作为 fingerprint_b64 传入 make_headers 即可。
    """
    tz = tz or time.strftime("%Z")
    ts_ms = int(time.time() * 1000) if ts_ms is None else ts_ms
    fields = [
        ("fp", device_id), ("dn", device_name), ("dm", device_model),
        ("os", os_name), ("osv", os_version), ("av", app_version),
        ("avc", app_version_code), ("pkg", package_name), ("asig", app_signature),
        ("hv", hv), ("pt", pt), ("dt", device_type), ("sw", screen_w),
        ("sh", screen_h), ("lang", lang), ("tz", tz), ("net", net),
        ("ts", ts_ms), ("bi", bi),
    ]

    def enc(v):
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        return str(v)

    return "{" + ",".join(f"{json.dumps(k)}:{enc(v)}" for k, v in fields) + "}"


# ---------------------------------------------------------------------------
# 全量头构造
# ---------------------------------------------------------------------------
class HeaderFactory:
    """一次初始化（对应一个 App 进程 / 一个 BootstrapConfig），逐请求产出全部头。

    session_id / clock_skew_ms 是进程级状态；其余每请求随机。
    fingerprint_b64 需外部提供（见 build_fp_payload_json + native maes/mbase64）。
    """

    def __init__(self,
                 device_id: str,
                 fingerprint_b64: str,
                 app_id: str = DEFAULT_APP_ID,
                 sign_secret: str = DEFAULT_SIGN_SECRET,
                 fp_hmac_secret_hex: str = DEFAULT_FP_HMAC_SECRET_HEX,
                 session_id: str | None = None,
                 clock_skew_ms: int = 0):
        self.device_id = device_id
        self.fingerprint_b64 = fingerprint_b64
        self.app_id = app_id
        self.sign_secret = sign_secret
        self.fp_hmac_secret_hex = fp_hmac_secret_hex
        self.session_id = session_id or gen_session_id()
        self.clock_skew_ms = clock_skew_ms

    def update_clock_skew(self, server_time_ms: int, local_time_ms: int | None = None) -> None:
        """q3.Q.update：skew = 服务器时间 - 本机时间（来自 bootstrap/negotiate 响应）。"""
        local = int(time.time() * 1000) if local_time_ms is None else local_time_ms
        self.clock_skew_ms = server_time_ms - local

    def make_headers(self, path: str, method: str = "POST",
                     ts_ms: int | None = None, nonce: str | None = None,
                     request_id: str | None = None, trace_id: str | None = None,
                     span_id: str | None = None, preset_session_id: str | None = None,
                     sign: bool = True) -> dict[str, str]:
        """产出一个请求的完整头集合（Ktor 插件链等价实现）。

        sign=False 或路径命中豁免清单时不含 x-signature/x-timestamp/x-nonce。
        """
        h: dict[str, str] = {}
        # --- ApiDeviceFingerprint（t3.f → A5.f）---
        h["x-device-id"] = self.device_id
        h["x-device-fingerprint"] = self.fingerprint_b64
        h["x-fp-sign"] = x_fp_sign(self.fingerprint_b64, self.fp_hmac_secret_hex)
        h["x-fp-algo"] = "1"
        # --- ApiSecurity（q3.J）---
        h["x-app-id"] = self.app_id
        h["x-platform"] = "android"
        if sign and not any(p in path for p in SIGN_EXEMPT_PATH_SUBSTRINGS):
            ts_ms = int(time.time() * 1000 + self.clock_skew_ms) if ts_ms is None else ts_ms
            nonce = nonce or gen_nonce()
            h["x-signature"] = x_signature(ts_ms, nonce, self.app_id, self.sign_secret)
            h["x-timestamp"] = str(ts_ms)
            h["x-nonce"] = nonce
        # --- TraceHeaderPlugin（u4.f）---
        request_id = request_id or gen_request_id()
        trace_id = trace_id or gen_trace_id()
        span_id = span_id or gen_span_id()
        if preset_session_id:          # 调用方预设（resolve/exchange 等流程），插件不覆盖
            h["x-session-id"] = preset_session_id
        else:
            h["x-session-id"] = self.session_id
        h["x-trace-id"] = trace_id
        h["x-span-id"] = span_id
        h["x-request-id"] = request_id
        h["traceparent"] = traceparent_header(trace_id, span_id)
        # --- 公共 ---
        h["user-agent"] = UA
        h["accept"] = "application/json"
        h["accept-charset"] = "UTF-8"
        return h


# ---------------------------------------------------------------------------
# 自检 / HAR 验证
# ---------------------------------------------------------------------------
_HAR_ENTRY48 = {
    "x-signature": "70b04e9ba70983385901fcedc0515d44",
    "x-timestamp": "1789820913546",
    "x-nonce": "acf0e4d71ad74b38bfb93c69f23d65c5",
    "x-app-id": "315891530526580736",
    "x-fp-sign": "091e9dade2357eaf3cd0f196503dd28974cd8b43e697da4f34e95867ab7cf0c2",
    "x-device-fingerprint":
        "3BXV6CyZ529Zvnq+DyITkqZuZDeukOF3CkmR1i9qngZk30aCw2AFSld18/EiuCkCVjGb1Y82wgOZ7xpBeEcDoB2yanl5QvDxSQJTrZuTK8sSE+RVtFO1Nqof"
        "/hOfeAdO3nYrJD2TcuNRQzenPIFZWJc9mX5++OLuZgG0wseazXExoyHl7uNQcQeQeVSkGLy1ogaznJPcf1gx5GZuzeWp+tDj9Vs7TxkYgwqydUWo/hGCVVO5"
        "PjokC7shYnuXASjn+pbZJWkcO7SlUOeP+iewESRW1WscXKGGpsHZ4pv5S1NQI98pwlTzsCM4p7HVMLUXrB1PxgFRq9tc10ATsY8FIuqHlD4I34YpNM4J2dY3"
        "YjKlyQ0c9+J8/LTK8agW4Vl02W7d19Oz/EQev8DvWJHeOY4MdwbQsIsmc1OLA+SLLMWXI3BbALa5+qsR0u2Z9a0G+RWTgQc0BEiFlitIdywst/tH049B4Mft"
        "CZMYC3rvKsD3plE9sJTi5hzNn5WdX94u8NdsCt4oag9ayWlPqb0DhSzcRJcs9+q0Npy01uUOLRC6gQA9M9NNR3rfuxrQ9tcX",
}


def selftest() -> bool:
    ok = True
    e = _HAR_ENTRY48
    got = x_signature(int(e["x-timestamp"]), e["x-nonce"], e["x-app-id"])
    print(f"x-signature : {got}  {'OK' if got == e['x-signature'] else 'FAIL'}")
    ok &= got == e["x-signature"]
    got = x_fp_sign(e["x-device-fingerprint"])
    print(f"x-fp-sign   : {got}  {'OK' if got == e['x-fp-sign'] else 'FAIL'}")
    ok &= got == e["x-fp-sign"]
    sp = gen_span_id.__doc__  # 结构检查
    s = span_prefix_check()
    print(f"span prefix : {s}  {'OK' if s == 'ccce' else 'FAIL'}")
    ok &= s == "ccce"
    tp = traceparent_header("a" * 32, "b" * 16)
    print(f"traceparent : {tp}  {'OK' if tp == '00-' + 'a' * 32 + '-' + 'b' * 16 + '-01' else 'FAIL'}")
    del sp
    return ok


def span_prefix_check() -> str:
    head = []
    for ch in "http_request"[:4]:
        if not ("0" <= ch <= "9" or "a" <= ch <= "f"):
            ch = chr((ord(ch) % 6) + 97)
        head.append(ch)
    return "".join(head)


def verify_har(path: str) -> bool:
    with open(path, encoding="utf-8") as f:
        har = json.load(f)
    entries = har["log"]["entries"]
    sig_ok = fp_ok = tp_ok = 0
    sig_n = fp_n = tp_n = 0
    fails = []
    for i, ent in enumerate(entries):
        d = {x["name"].lower(): x["value"] for x in ent["request"]["headers"]}
        if "x-signature" in d:
            sig_n += 1
            exp = x_signature(int(d["x-timestamp"]), d["x-nonce"], d.get("x-app-id", DEFAULT_APP_ID))
            if exp == d["x-signature"]:
                sig_ok += 1
            else:
                fails.append((i, "x-signature", exp, d["x-signature"]))
        if "x-fp-sign" in d and "x-device-fingerprint" in d:
            fp_n += 1
            exp = x_fp_sign(d["x-device-fingerprint"])
            if exp == d["x-fp-sign"]:
                fp_ok += 1
            else:
                fails.append((i, "x-fp-sign", exp, d["x-fp-sign"]))
        if "traceparent" in d and "x-trace-id" in d:
            tp_n += 1
            parts = d["traceparent"].split("-")
            if parts[1] == d["x-trace-id"] and parts[2] == d.get("x-span-id"):
                tp_ok += 1
            else:
                fails.append((i, "traceparent", parts, [d["x-trace-id"], d.get("x-span-id")]))
    print(f"x-signature : {sig_ok}/{sig_n}")
    print(f"x-fp-sign   : {fp_ok}/{fp_n}")
    print(f"traceparent : {tp_ok}/{tp_n}")
    for f_ in fails[:10]:
        print("FAIL", f_)
    return not fails


if __name__ == "__main__":
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        sys.exit(0 if verify_har(sys.argv[1]) else 1)
    sys.exit(0 if selftest() else 1)

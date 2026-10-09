# -*- coding: utf-8 -*-
"""Myuko 纯 Python 客户端 —— **零抓包**，全流程自举。

自举链：
    GET auth/bootstrap.jpg  → AES-256-CBC 解密 → {masterSecret, signSecret,
                                                   fpAlgo.hmacSecret, mbase64Table}
    本地生成 deviceId + x-device-fingerprint（服务端不校验指纹内容，只校验 x-fp-sign）
    POST auth/negotiate     → 服务端回显 deviceSecret（应等于本地 masterKey）
    search / detail / episodes / play

用法：
    python myuko_pure.py demo                     # 全链路演示
    python myuko_pure.py search 火影忍者
    python myuko_pure.py play <videoId> <code> <ep>

依赖：magic_v3.py（v3 帧）、signing.py（请求头）、bootstrap_keys.py（bootstrap 解密）、ecsm.py
"""
from __future__ import annotations

import base64
import hashlib
import gzip
import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bootstrap_keys as BK
import magic_v3 as M
import signing

BASE = "https://rgxbm.xiaoxiangkj.com"

# ------------------------------------------------------------------ DoH 容灾
# 应用内建了「寻址与多端点容灾」（addressing/v1，见 work/analysis/appdata_pull/）：
#   policy.probe_order = [tcp, https, udp, doh]，probe_timeout_ms=2000
#   doh.resolvers = [dns.alidns.com, 223.6.6.6, doh.pub, 120.53.53.53]
#   doh.recovery_names = [2090385866238025728.{aiappai.net,adappad.com,acappac.com}]
#     ↑ 这 3 个恢复名目前**没有 DNS 记录**（是主域名被墙时才激活的），所以用不上。
# 但 DoH 本身有用：主域名系统解析一旦被污染/失败，整站就全挂。
# 这里加一层兜底 —— 系统 DNS 失败时改用 DoH 解析出的 IP 直连（SNI/Host 仍用域名）。
DOH_RESOLVERS = ["https://dns.alidns.com/resolve", "https://doh.pub/dns-query"]
_doh_cache: dict[str, list] = {}


def doh_resolve(host: str, ctx=None) -> list:
    """用 DoH 解析域名（返回 A 记录 IP 列表）。"""
    if host in _doh_cache:
        return _doh_cache[host]
    ctx = ctx or ssl.create_default_context()
    for base in DOH_RESOLVERS:
        try:
            u = f"{base}?name={host}&type=A"
            r = urllib.request.urlopen(
                urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0",
                                                   "Accept": "application/dns-json"}),
                timeout=8, context=ctx)
            j = json.loads(r.read())
            ips = [a["data"] for a in (j.get("Answer") or []) if a.get("type") == 1]
            if ips:
                _doh_cache[host] = ips
                return ips
        except Exception:
            continue
    return []


class _HostConn(http.client.HTTPSConnection):
    """连到指定 IP，但 SNI 仍用域名（绕过 DNS）。"""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _Resp:
    """把 http.client 的响应包成 urlopen 那样（只需要 status/headers/read）。"""

    def __init__(self, r):
        self._r = r
        self.status = r.status
        self.headers = r.headers

    def read(self):
        return self._r.read()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._r.close()


def _direct_by_ip(host, ip, url, headers=None, data=None, timeout=25, ctx=None):
    u = urllib.parse.urlsplit(url)
    path = u.path + (("?" + u.query) if u.query else "")
    conn = _HostConn(host, ip, timeout=timeout, context=ctx)
    h = dict(headers or {})
    h.setdefault("Host", host)
    conn.request("POST" if data else "GET", path, body=data, headers=h)
    return _Resp(conn.getresponse())


def open_url(url, headers=None, data=None, timeout=25, ctx=None):
    """带 DoH 兜底的请求：先走系统 DNS；解析/连接失败则用 DoH 结果直连 IP。"""
    def _req():
        return urllib.request.Request(url, data=data, headers=headers or {})

    try:
        return urllib.request.urlopen(_req(), timeout=timeout, context=ctx)
    except (urllib.error.URLError, socket.gaierror, OSError) as ex:
        host = urllib.parse.urlsplit(url).hostname
        if not host or "://" not in url or not url.startswith("https"):
            raise
        ips = doh_resolve(host, ctx)
        if not ips:
            raise
        print(f"[doh] 系统 DNS/连接失败({type(ex).__name__})，改用 DoH：{host} → {ips[0]}")
        return _direct_by_ip(host, ips[0], url, headers, data, timeout, ctx)

UA = "Myuko Ktor Client"
# 段链可任选（服务端只用帧里的 km 还原 id）。用四段混合链，兼顾混淆强度。
DEFAULT_CHAIN = (0x19, 0xE4, 0x75, 0x82)


# --------------------------------------------------------------------- mbase64
def mbase64_encode(data: bytes, table: str) -> str:
    """自定义字母表 base64（表来自 bootstrap 配置的 mbase64Table.tableStr）。"""
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert len(table) == 64, "mbase64Table 必须是 64 字符"
    return base64.b64encode(data).decode().translate(str.maketrans(std, table))


def mbase64_decode(text: str, table: str) -> bytes:
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return base64.b64decode(text.translate(str.maketrans(table, std)))


# --------------------------------------------------------------------- 客户端
class Myuko:
    def __init__(self, config: dict, device_id: str | None = None,
                 fingerprint_b64: str | None = None, chain=DEFAULT_CHAIN,
                 base: str = BASE, timeout: int = 25):
        self.base = base
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.cfg = config
        self.chain = tuple(chain)
        self.master_secret = config["masterSecret"]
        self.mb64_table = (config.get("mbase64Table") or {}).get("tableStr") or ""
        # --- 设备身份（可外部指定；否则本地确定性生成）---
        self.device_id = device_id or self._gen_device_id()
        self.fingerprint = fingerprint_b64 or self._gen_fingerprint()
        self.mk = M.master_key(self.master_secret, self.device_id)
        self.hdr = signing.HeaderFactory(
            device_id=self.device_id, fingerprint_b64=self.fingerprint,
            sign_secret=config.get("signSecret") or signing.DEFAULT_SIGN_SECRET,
            fp_hmac_secret_hex=(config.get("fpAlgo") or {}).get("hmacSecret")
            or signing.DEFAULT_FP_HMAC_SECRET_HEX)
        self.negotiate_info: dict | None = None

    # ---------- 设备身份 ----------
    @staticmethod
    def _gen_device_id(seed: str | None = None) -> str:
        """deviceId = hex(SHA-256(material))；material 的 sourceType=uuid_timestamp 每次安装换新。"""
        import deviceid
        src = deviceid.uuid_timestamp_source()
        mat = "\n".join([
            deviceid._kv("ruleVersion", "4"),
            deviceid._kv("sourceType", "uuid_timestamp"),
            deviceid._kv("sourceValueHash", hashlib.sha256(src.encode()).hexdigest()),
            deviceid._kv("hardwareFingerprint", deviceid.build_json(
                board="goldfish", brand="google", device="generic", hardware="ranchu",
                manufacturer="Google", model="sdk_gphone64_x86_64",
                product="sdk_gphone64_x86_64")),
        ])
        return hashlib.sha256(mat.encode()).hexdigest()

    @staticmethod
    def _gen_fingerprint_for(device_id: str) -> str:
        raw = hashlib.sha256(("fp:" + device_id).encode()).digest() + \
              hashlib.sha256(("fp2:" + device_id).encode()).digest()[:18]
        return base64.b64encode(raw).decode()

    def _gen_fingerprint(self) -> str:
        """服务端不校验指纹内容（只校验 x-fp-sign），这里做确定性生成，长度对齐真实样本。"""
        return self._gen_fingerprint_for(self.device_id)

    # ---------- 自举 ----------
    @staticmethod
    def fetch_config(device_id: str | None = None, base: str = BASE) -> dict:
        """GET bootstrap.jpg（需带完整请求头，裸请求会拿到不同加密配置）→ 解密出配置。

        配置（masterSecret / signSecret / fpAlgo.hmacSecret / mbase64Table）与设备无关，
        可以只取一次，然后给任意多个 deviceId 复用。
        """
        ctx = ssl.create_default_context()
        did = device_id or Myuko._gen_device_id()
        fp = Myuko._gen_fingerprint_for(did)
        tmp = signing.HeaderFactory(device_id=did, fingerprint_b64=fp)
        path = (f"/api/v1/app/client/auth/bootstrap.jpg?appId={BK.APP_ID}&sv=1"
                f"&_t={int(time.time() * 1000)}")
        h = tmp.make_headers(path, "GET", sign=False)
        h["user-agent"] = UA
        r = open_url(base + path, headers=h, timeout=25, ctx=ctx)   # 带 DoH 兜底
        cfg, _ = BK.decrypt_bootstrap_config(r.read(), unix_sec=int(time.time()))
        return cfg

    @classmethod
    def bootstrap(cls, device_id: str | None = None, base: str = BASE, **kw) -> "Myuko":
        cfg = cls.fetch_config(device_id=device_id, base=base)
        obj = cls(cfg, device_id=device_id, base=base, **kw)
        if cfg.get("serverTime"):
            obj.hdr.update_clock_skew(cfg["serverTime"])
        return obj

    # ---------- HTTP ----------
    def _http(self, url, data=None, headers=None):
        r = open_url(url, data=data, headers=headers or {},
                     timeout=self.timeout, ctx=self.ctx)        # 带 DoH 兜底
        raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return r.status, raw

    def api(self, path: str, obj: dict, sign: bool = True) -> dict:
        h = self.hdr.make_headers(path, "POST", sign=sign)
        h["content-type"] = "application/octet-stream"
        h["accept-encoding"] = "gzip"
        frame = M.pack(self.mk, json.dumps(obj, separators=(",", ":")).encode(),
                       M.slot_of(int(time.time())), chain=self.chain)
        _, raw = self._http(self.base + path, frame, h)
        return json.loads(M.unpack(raw, self.mk))

    # ---------- 业务 ----------
    def negotiate(self) -> dict:
        d = self.api("/api/v1/app/client/auth/negotiate",
                     {"deviceId": self.device_id, "platform": "android"}, sign=False)
        if d.get("timestamp"):
            self.hdr.update_clock_skew(d["timestamp"])
        self.negotiate_info = d.get("data", {})
        return d

    def search(self, keyword: str, page: int = 1, size: int = 10) -> list:
        d = self.api("/api/v1/app/client/video/search",
                     {"keyword": keyword, "pageIndex": page, "pageSize": size,
                      "categoryId": "", "tags": ""})
        return ((d.get("data") or {}).get("videos")) or []

    def detail(self, video_id: str) -> dict:
        d = self.api("/api/v1/app/client/video/detail", {"videoId": video_id})
        return ((d.get("data") or {}).get("video")) or {}

    def episodes(self, video_id: str, code: str) -> list:
        d = self.api("/api/v1/app/client/resolve/episodes",
                     {"videoId": video_id, "code": code})
        return ((d.get("data") or {}).get("episodes")) or []

    def _sign(self, vid, code, ep, action, params):
        d = self.api("/api/v1/app/client/resolve/sign",
                     {"videoId": vid, "code": code, "episodeNum": ep,
                      "action": action, "params": params})
        return d.get("data", {}).get("sign", d.get("data"))

    def play(self, video_id: str, code: str, ep: int, quality: str = "1080p") -> list:
        qd = (self.api("/api/v1/app/client/resolve/qualities",
                       {"videoId": video_id, "code": code, "episodeNum": ep,
                        "caps": ["v2ts"]}).get("data") or {})
        ed = (self.api("/api/v1/app/client/resolve/exchange",
                       {"videoId": video_id, "code": code, "episodeNum": ep,
                        "quality": quality, "exchangeToken": qd.get("exchangeToken"),
                        "caps": ["v2ts"]}).get("data") or {})
        source = ed.get("originalUrl")
        if not source:
            raise RuntimeError(f"exchange 未返回 originalUrl: {ed}")
        s1 = self._sign(video_id, code, ep, "get_api_url", source)
        api_url = s1.get("api_url", "")
        hdrs = dict(s1.get("headers") or {})
        hdrs["User-Agent"] = "okhttp/3.12.1"
        is_new_api = s1.get("is_new_api")
        _, resp = self._http(api_url, None, hdrs)
        if is_new_api:
            plain = resp
        else:
            dec = self._sign(video_id, code, ep, "decrypt_response",
                             base64.b64encode(resp).decode())
            plain = dec if isinstance(dec, str) else json.dumps(dec)
        obj = json.loads(plain)
        out = []
        for pa in (obj.get("data") or {}).get("playAddr") or []:
            pr = self._sign(video_id, code, ep, "process_url",
                            {"playAddr": pa, "is_new_api": is_new_api}) or {}
            out.append({"quality": pa.get("desc") or pa.get("title"),
                        "vcodec": pa.get("vcodec"), "format": pa.get("format"),
                        "type": pr.get("type"), "url": pr.get("url")})
        return out

    def m3u8(self, url: str) -> str:
        _, raw = self._http(url, None, {"User-Agent": "okhttp/3.12.1", "Accept": "*/*"})
        return raw.decode("utf-8", "replace")


# --------------------------------------------------------------------- CLI
def _demo():
    print("① 自举 bootstrap.jpg（零抓包）")
    c = Myuko.bootstrap()
    print(f"   masterSecret = {c.master_secret}")
    print(f"   signSecret   = {c.cfg.get('signSecret')}")
    print(f"   mbase64 表   = {c.mb64_table}")
    print(f"   本机 deviceId = {c.device_id}")
    print(f"   本机 masterKey = {c.mk.decode()}")

    print("\n② negotiate")
    n = c.negotiate()
    ds = (n.get("data") or {}).get("deviceSecret")
    print(f"   code={n.get('code')}  服务端 deviceSecret={ds}")
    print(f"   校验: {'✅ 一致' if ds == c.mk.decode() else '❌ 不一致'}")

    print("\n③ search 火影忍者")
    vs = c.search("火影忍者")
    for v in vs[:5]:
        print(f"   {v['id']}  {v.get('title')}")
    if not vs:
        return
    v = vs[0]
    det = c.detail(v["id"])
    code = (det.get("player") or [{}])[0].get("playerCode") or "cn"
    eps = c.episodes(v["id"], code)
    print(f"\n④ detail  {det.get('title')} {det.get('year')} 评分{det.get('score')} "
          f"线路={code} 集数={len(eps)}")

    print("\n⑤ play")
    urls = c.play(v["id"], code, 1)
    for u in urls:
        print(f"   {u['quality']} {u['vcodec']} {u['type']} → {u['url']}")
    if urls:
        txt = c.m3u8(urls[0]["url"])
        segs = [l for l in txt.splitlines() if l and not l.startswith("#")]
        print(f"   m3u8 {len(segs)} 段，首段 {segs[0] if segs else '-'}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd == "demo":
        _demo()
    else:
        cli = Myuko.bootstrap()
        cli.negotiate()
        if cmd == "search":
            for v in cli.search(sys.argv[2]):
                print(v["id"], v.get("title"))
        elif cmd == "play":
            vid = sys.argv[2]
            code = sys.argv[3] if len(sys.argv) > 3 else "cn"
            ep = int(sys.argv[4]) if len(sys.argv) > 4 else 1
            for u in cli.play(vid, code, ep):
                print(json.dumps(u, ensure_ascii=False))

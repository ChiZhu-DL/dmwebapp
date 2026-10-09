# -*- coding: utf-8 -*-
"""动漫共和国 本地网页播放站（端口 8000）。

- 后端：纯 Python（stdlib http.server），复用 myuko_pure 的自举客户端
- 前端：单页（搜索 / 结果网格 / 详情 / 剧集 / hls.js 播放）
- 代理：m3u8 重写 + 分片转发，绕开 CDN 的 CORS 与防盗链

启动：python webapp_server.py            → http://127.0.0.1:8000
"""
from __future__ import annotations

import atexit
import gzip
import hashlib
import io
import json
import os
import secrets
import ssl
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import myuko_pure as MP

PORT = 8000
UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/122.0 Safari/537.36")
_ctx = ssl.create_default_context()
_lock = threading.Lock()

# ===================================================================== 安全配置
# 访问令牌：设了就必须带 ?k=<token>（会种 Cookie）才能用。空 = 不鉴权（仅建议本机用）
ACCESS_TOKEN = os.environ.get("MYUKO_TOKEN", "").strip()
# 允许代理的上游域名后缀（防 SSRF）。逗号分隔，可用 MYUKO_ALLOW_HOSTS 追加
ALLOW_HOST_SUFFIX = [h.strip().lower() for h in os.environ.get(
    "MYUKO_ALLOW_HOSTS",
    "aliyuncs.com,xhscdn.com,yximgs.com,nxjunyu.asia,adukwai.com,meituan.net,"
    "baidu.com,ecombdimg.com,ykimg.com,sigmob.cn,xiaoxiangkj.com,hzhcbkj.cn,"
    "xiaohongshu.com,edu-cloud-os.oss-accelerate.aliyuncs.com"
).split(",") if h.strip()]
# 限流（每 IP，每 60 秒）
RATE_LIMITS = {"/api/search": 30, "/api/detail": 60, "/api/episodes": 30,
               "/api/play": 30, "/api/tc": 6, "/api/seg": 3000, "/api/img": 300}
RATE_MAX_SEG_MB = 6000          # 单 IP 每分钟最多拉多少 MB 分片（防带宽刷爆）
MAX_TRANSCODES = 2              # 同时最多几个转码会话
_RATE: dict[str, list] = {}
_RATE_LOCK = threading.Lock()


def client_ip(handler) -> str:
    for h in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        v = handler.headers.get(h)
        if v:
            return v.split(",")[0].strip()
    return handler.client_address[0]


def hmac_compare(a, b) -> bool:
    import hmac as _hmac
    try:
        return _hmac.compare_digest(str(a), str(b))
    except Exception:
        return False


def rate_ok(ip: str, path: str) -> bool:
    """按 **(IP, 路径)** 分别限流。
    ★ 不能只按 IP 存一个数组 —— 那样页面加载时的一堆 /api/img、/api/play 请求
      会把数组填满，导致后面正常的 /api/tc 直接 429（实测踩过这个坑）。
    """
    limit = RATE_LIMITS.get(path)
    if not limit:
        return True
    key = (ip, path)
    now = time.time()
    with _RATE_LOCK:
        arr = _RATE.setdefault(key, [])
        arr[:] = [t for t in arr if now - t < 60]
        if len(arr) >= limit:
            return False
        arr.append(now)
        if len(_RATE) > 5000:
            for k in list(_RATE)[:2000]:
                _RATE.pop(k, None)
    return True


# ★ 运行时学习到的播放域名。CDN 域名是会轮换的（实测同一集昨天在 nxjunyu.asia、
#   今天就变成 v4-kling.kechuangai.com），写死在白名单里必然漏；而漏了的后果不是
#   「少个功能」而是**整条播放/转码链被 403 拦死**。
#   白名单的本意是「挡住客户端随手塞进来的内网地址」，不是挡官方接口给的 CDN ——
#   所以从 play 接口解析出来的域名自动进白名单（内网/IP 的限制依然生效）。
_LEARNED_HOSTS: set[str] = set()


def learn_hosts(urls) -> list:
    """记住 play 接口返回的所有 http(s) 域名，返回原样（方便直接串联调用）。"""
    for it in urls or []:
        if not isinstance(it, dict):
            continue
        for k in ("url", "direct", "play", "proxy"):
            v = it.get(k)
            if isinstance(v, str) and v.startswith("http"):
                _remember_host(v)
    return urls


def _remember_host(u: str) -> str | None:
    h = (urllib.parse.urlparse(u).hostname or "").lower()
    if h and h not in _LEARNED_HOSTS and h not in ALLOW_HOST_SUFFIX:
        _LEARNED_HOSTS.add(h)
        print(f"[net] 记住域名：{h}")
        return h
    return None


def learn_m3u8_hosts(text: str, base: str) -> int:
    """记住**播放列表里出现**的分片 / 密钥域名。

    ★ 为什么必须单独做这件事：分片 CDN 常与 m3u8 不同域，而且只在播放列表正文里出现。
      实测 m3u8 在 `img.nxjunyu.asia`，分片却在 `p4-plat.wskwai.com`（另一集是
      `h23.static.yximgs.com` / `edu-cloud-os...aliyuncs.com`，天天换）。
      不记 → 本机代理一律 403 → 转码和直连全断，且报错看着像「CDN 挂了」。
    """
    n = 0
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("#"):
            if 'URI="' in s:
                s = s.split('URI="', 1)[1].split('"', 1)[0]
            else:
                continue
        if not s:
            continue
        try:
            n += 1 if _remember_host(urllib.parse.urljoin(base, s)) else 0
        except Exception:
            pass
    return n


def host_allowed(url: str) -> bool:
    """只允许代理白名单域名，且禁止指向内网/回环地址。"""
    try:
        pr = urllib.parse.urlparse(url)
    except Exception:
        return False
    if pr.scheme not in ("http", "https"):
        return False
    host = (pr.hostname or "").lower()
    if not host:
        return False
    # 禁止 IP 直连（含内网、回环、链路本地、元数据地址）
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return False
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
        return False        # 一律不允许直接用 IP，必须走白名单域名
    except ValueError:
        pass
    if host in _LEARNED_HOSTS:      # 本服务自己解析出来的播放域名
        return True
    return any(host == s or host.endswith("." + s) for s in ALLOW_HOST_SUFFIX)



# --------------------------------------------------------------------- 客户端
# ★ 设备池：不使用抓包里的真实 deviceId，而是随机生成一批（服务端不校验 deviceId 来源）。
#   这样即使某个身份被风控封了，也只影响 1/N，且随时可扩容/重置。
DEVICE_POOL_SIZE = max(1, int(os.environ.get("MYUKO_POOL", "8")))
_CFG: dict | None = None
_POOL: list[MP.Myuko] = []
_POOL_LOCK = threading.Lock()
_tls = threading.local()


def _new_client(cfg: dict) -> MP.Myuko:
    did = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    c = MP.Myuko(cfg, device_id=did)
    c.negotiate()
    return c


def _ensure_pool() -> list[MP.Myuko]:
    global _CFG
    with _POOL_LOCK:
        if _CFG is None:
            probe = MP.Myuko.bootstrap()          # 拉一次 bootstrap 配置（与设备无关）
            _CFG = probe.cfg
            _POOL.append(probe)
        while len(_POOL) < DEVICE_POOL_SIZE:
            try:
                _POOL.append(_new_client(_CFG))
            except Exception as ex:
                print(f"[pool] 建号失败（已有 {len(_POOL)}）: {ex}")
                break
    return list(_POOL)


def set_visitor(v: str | None):
    _tls.visitor = v


def get_client() -> MP.Myuko:
    """按访客分配池中的一个设备身份（同一访客稳定命中同一个）。"""
    pool = _ensure_pool()
    v = getattr(_tls, "visitor", None)
    if not v or len(pool) == 1:
        return pool[0]
    idx = int(hashlib.sha256(v.encode()).hexdigest()[:8], 16) % len(pool)
    return pool[idx]


def reset_pool():
    """重建全部设备身份（被封/想换一批时用）。"""
    global _CFG
    with _POOL_LOCK:
        _POOL.clear()
        _CFG = None
    _ensure_pool()


def with_retry(fn):
    """业务调用失败时重建该身份重试一次（会话/配置过期）。"""
    try:
        return fn(get_client())
    except Exception:
        c = get_client()
        try:
            c.negotiate()
        except Exception:
            pass
        return fn(c)



# --------------------------------------------------------------------- 上游取流
def fetch(url: str, headers: dict | None = None, timeout: int = 25):
    h = {"User-Agent": UA_BROWSER, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    r = urllib.request.urlopen(req, timeout=timeout, context=_ctx)
    raw = r.read()
    if r.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    return r.status, raw, dict(r.headers)


# --------------------------------------------------------------------- 路由
def api_search(q):
    kw = q.get("keyword", [""])[0].strip()
    page = int(q.get("page", ["1"])[0] or 1)
    size = int(q.get("size", ["20"])[0] or 20)
    if not kw:
        return {"ok": False, "msg": "缺少 keyword"}
    vs = with_retry(lambda c: c.search(kw, page, size))
    items = [{
        "id": v.get("id"), "title": v.get("title"),
        "subTitle": v.get("subTitle"), "year": v.get("year"),
        "score": v.get("score"), "cover": v.get("coverUrl") or v.get("posterUrl") or "",
        "tags": v.get("tags"), "custom": v.get("customText"),
        "updateInfo": v.get("updateInfo") or v.get("remark"),
    } for v in vs]
    return {"ok": True, "count": len(items), "items": items}


def api_detail(q):
    vid = q.get("videoId", [""])[0]
    if not vid:
        return {"ok": False, "msg": "缺少 videoId"}
    d = with_retry(lambda c: c.detail(vid))
    return {"ok": True, "video": {
        "id": d.get("id"), "title": d.get("title"), "year": d.get("year"),
        "score": d.get("score"), "tags": d.get("tags"), "area": d.get("area"),
        "cover": d.get("coverUrl") or "", "description": d.get("description"),
        "totalEpisodes": d.get("totalEpisodes"), "currentEpisodes": d.get("currentEpisodes"),
        "isFinished": d.get("isFinished"), "playCount": d.get("playCount"),
        "players": d.get("player") or [],
    }}


def api_episodes(q):
    vid = q.get("videoId", [""])[0]
    code = q.get("code", [""])[0]
    if not vid or not code:
        return {"ok": False, "msg": "缺少 videoId/code"}
    eps = with_retry(lambda c: c.episodes(vid, code))
    return {"ok": True, "count": len(eps), "episodes": [
        {"n": e.get("episodeNum"), "name": e.get("displayName") or e.get("episodeName"),
         "code": e.get("code"), "vip": e.get("isVip")} for e in eps]}


def api_play(q):
    vid = q.get("videoId", [""])[0]
    code = q.get("code", [""])[0]
    ep = int(q.get("ep", ["1"])[0] or 1)
    quality = q.get("quality", ["1080p"])[0]
    direct = q.get("direct", ["1"])[0] != "0"
    if not vid or not code:
        return {"ok": False, "msg": "缺少 videoId/code"}
    urls = learn_hosts(with_retry(lambda c: c.play(vid, code, ep, quality)))
    if not urls:
        return {"ok": False, "msg": "未取到播放地址"}
    opts = []
    for u in urls:
        url = u.get("url") or ""
        kind = "hls" if (u.get("type") == "hls" or ".m3u8" in url.lower()) else "mp4"
        # ★ MP4 直接给直链（浏览器可跨域播，零服务器带宽）
        #   HLS 只有 m3u8 需要过一下（CDN 不给 CORS），分片仍写直链
        play = url if (kind == "mp4" or not direct) else \
            "/api/m3u8?u=" + urllib.parse.quote(url, safe="") + "&direct=1"
        if not direct:
            play = proxy_url(url)
        opts.append({**u, "kind": kind, "direct": url,
                     "play": play, "proxy": proxy_url(url)})
    def rank(o):
        s = (o.get("quality") or "").upper()
        return {"4K": 4000, "2160P": 2160, "1080P": 1080, "720P": 720}.get(s, 0)
    opts.sort(key=rank, reverse=True)
    return {"ok": True, "play": opts[0], "all": opts,
            "mode": "direct" if direct else "proxy"}


def api_kazumi_chapters(q, host="", scheme="http"):
    """Kazumi 内置数据源：一次给出「线路 -> 剧集」。

    ⚠️ 这里**不解析播放地址**（逐集跑六算法链太重，打开详情页会卡住），
    只给每集一个「按需解析」的 URL —— 选中哪一集才解析哪一集。

    ⚠️ 剧集地址必须是**绝对 URL**：客户端对相对路径会用规则里的 `baseURL` 去拼，
    而 MuMu 模拟器里的 `127.0.0.1` 指向模拟器自己（宿主要走 10.0.2.2）
    → 现象是 `tcp: Connection to tcp://127.0.0.1:8000 failed: Connection refused`。
    所以用请求的 Host 头拼绝对地址。
    """
    prefix = ("%s://%s" % (scheme, host)) if host else ""
    vid = q.get("videoId", [""])[0]
    if not vid:
        return {"ok": False, "msg": "缺少 videoId"}
    k = q.get("k", [""])[0]
    try:
        d = with_retry(lambda c: c.detail(vid))
    except Exception as ex:
        return {"ok": False, "msg": "detail 失败: %s" % ex}
    roads = []
    for pl in (d.get("player") or []):
        code = pl.get("playerCode") or pl.get("code") or ""
        if not code:
            continue
        name = pl.get("playerName") or pl.get("name") or code
        try:
            eps = with_retry(lambda c: c.episodes(vid, code))
        except Exception:
            continue
        if not eps:
            continue
        roads.append({
            "name": name,
            "episodes": [
                {"name": (e.get("displayName") or e.get("episodeName")
                          or ("第%02d集" % (e.get("episodeNum") or (i + 1)))),
                 "url": prefix + "/api/kazumi/play.m3u8?" + urllib.parse.urlencode(
                     {"videoId": vid, "code": code,
                      "ep": e.get("episodeNum") or (i + 1), "k": k})}
                for i, e in enumerate(eps)
            ],
        })
    return {"ok": True, "roads": roads}


def api_kazumi_qualities(q):
    """返回某一集可选的画质档位（播放页「画质」菜单用）。

    只在用户点开画质菜单时才请求 —— 打开详情页时不解析，避免逐集跑六算法链。
    """
    vid = q.get("videoId", [""])[0]
    code = q.get("code", [""])[0]
    ep = int(q.get("ep", ["1"])[0] or 1)
    if not vid or not code:
        return {"ok": False, "msg": "缺少 videoId/code"}
    try:
        urls = learn_hosts(with_retry(lambda c: c.play(vid, code, ep, "1080p")))
    except Exception as ex:
        return {"ok": False, "msg": "解析失败: %s" % ex}
    items, seen = [], set()
    for u in urls:
        quality = (u.get("quality") or "").upper()
        if not quality or quality in seen:
            continue
        seen.add(quality)
        raw = u.get("url") or ""
        kind = "hls" if (u.get("type") == "hls" or ".m3u8" in raw.lower()) else "mp4"
        items.append({"quality": quality, "kind": kind})
    rank = {"4K": 4000, "2160P": 2160, "1080P": 1080, "720P": 720, "480P": 480}
    items.sort(key=lambda o: rank.get(o["quality"], 0), reverse=True)
    return {"ok": True, "items": items}


def api_kazumi_play(q):
    """Kazumi 内置数据源：解析出一集的真实媒体地址。

    HLS → 直接回重写后的 m3u8（分片写绝对直链，服务器零带宽）；
    MP4  → 交给调用方 302 跳到直链（返回里带 kind 供判断）。
    """
    want = (q.get("quality", [""])[0] or "").upper()
    # ⚠️ **不能把 quality 透传给 api_play**：api_play 会把它当 `c.play()` 的入参，
    #    传 "4K" 会让上游 exchange 环节直接抛
    #    `RuntimeError: exchange 未返回 originalUrl: {}`（实测 500）。
    #    正确做法：用默认档位拿**全量**列表（`all` 里本来就含 4K），再自己挑。
    q2 = dict(q)
    q2["quality"] = ["1080p"]
    r = api_play(q2)
    if not r.get("ok"):
        return r
    opt = r.get("play") or {}
    if want:
        for candidate in (r.get("all") or []):
            if (candidate.get("quality") or "").upper() == want:
                opt = candidate
                break
    url = opt.get("direct") or opt.get("play") or ""
    if not url:
        return {"ok": False, "msg": "未取到播放地址"}
    return {"ok": True, "kind": opt.get("kind"), "url": url,
            "quality": (opt.get("quality") or "").upper()}


def proxy_url(u: str) -> str:
    """本机分片/密钥代理地址。

    ⚠️ **必须带令牌**：`/api/seg` 和别的端点一样要过 `_authed()`，
    而 mpv 播放器不会带浏览器的 Cookie —— 加密档位的 `#EXT-X-KEY` 走这里，
    漏了令牌就是 401（现象：视频起播但一直解不开、黑屏/卡住）。
    """
    tok = ("&k=" + urllib.parse.quote(ACCESS_TOKEN)) if ACCESS_TOKEN else ""
    return "/api/seg?u=" + urllib.parse.quote(u, safe="") + tok


def rewrite_m3u8(text: str, base_url: str, direct: bool = False) -> str:
    """m3u8 地址重写。
    direct=True  → 分片写成**绝对直链**（CDN 带 CORS，浏览器直连，服务器零带宽）
    direct=False → 全部走本机 /api/seg 代理（兜底）

    ★ URI="..."（#EXT-X-KEY / #EXT-X-MAP）**始终走本机代理**：
      密钥只有 16 字节、init 段也很小，但很多 CDN 不给 CORS，
      且 key 的 URI 常是根路径相对地址，直连极易失败（AES-128 流会整段解不开）。
    """
    learn_m3u8_hosts(text, base_url)     # 分片/密钥域名也进白名单，否则本机代理会 403

    def seg(u: str) -> str:
        absu = urllib.parse.urljoin(base_url, u)
        return absu if direct else proxy_url(absu)

    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            out.append(line)
            continue
        if s.startswith("#"):
            if 'URI="' in s:            # 密钥 / init 段 → 一律代理
                pre, _, rest = s.partition('URI="')
                uri, _, post = rest.partition('"')
                out.append(f'{pre}URI="{proxy_url(urllib.parse.urljoin(base_url, uri))}"{post}')
            else:
                out.append(line)
        else:
            out.append(seg(s))
    return "\n".join(out) + "\n"


def _q_rank(o) -> int:
    s = (o.get("quality") or "").upper()
    return {"4K": 4000, "2160P": 2160, "1080P": 1080, "720P": 720}.get(s, 0)


def pick_source_for_height(urls: list, h: int) -> dict:
    """为转码挑源：优先「≥ 目标高度的最小档」（省解码），没有就取最大的。"""
    up = [o for o in urls if _q_rank(o) >= h]
    return min(up, key=_q_rank) if up else max(urls, key=_q_rank)


def open_upstream(u: str, range_hdr: str | None = None, timeout: int = 60):
    """打开上游连接（流式），支持 Range 透传。"""
    h = {"User-Agent": "okhttp/3.12.1", "Accept": "*/*", "Accept-Encoding": "identity"}
    if range_hdr:
        h["Range"] = range_hdr
    return urllib.request.urlopen(urllib.request.Request(u, headers=h),
                                  timeout=timeout, context=_ctx)


# --------------------------------------------------------------------- 兼容转码
# 源多为 H.265(HEVC)。浏览器能不能播 HEVC 取决于**操作系统有没有 HEVC 解码器**，
# 网页层面无法「内置」——所以这里用 ffmpeg 实时转 H.264 HLS 当兼容层，任何设备都能播。
#   实测：4K→4K libx264 veryfast 1.69x / h264_amf 3.06x 实时；4K→1080p 3.35x
#   会话按 (videoId|code|ep|高度) 缓存，重看不重转。
import shutil
import subprocess
import tempfile
import uuid

TC_ROOT = os.path.join(tempfile.gettempdir(), "myuko_tc")
SESSIONS: dict[str, dict] = {}          # sid -> {...}
TC_BY_KEY: dict[str, str] = {}          # "vid|code|ep|h" -> sid（缓存命中就不重转）
TC_LOCK = threading.Lock()
# 按目标高度给码率（4K 给足，否则糊）
BITRATE = {2160: "14M", 1440: "9M", 1080: "6M", 720: "3M", 480: "1500k"}


def find_ffmpeg() -> str | None:
    cands = [shutil.which("ffmpeg")]
    la = os.environ.get("LOCALAPPDATA", "")
    cands += [os.path.join(la, r"Microsoft\WinGet\Links\ffmpeg.exe"),
              r"C:\ffmpeg\bin\ffmpeg.exe", r"C:\Program Files\ffmpeg\bin\ffmpeg.exe"]
    for c in cands:
        if c and os.path.exists(c):
            return c
    return None


FFMPEG = find_ffmpeg()

# 编码器候选（按优先级）。每个都**按目标分辨率 + 目标码率实跑**验证 ——
# ffmpeg「列出」nvenc/qsv 不代表机器有对应硬件；更要紧的是**同一个编码器在小分辨率
# 能跑、到 4K 未必能跑**：实测 h264_amf 在 3840x2160 + 10bit(p010) 输入下
# `encoder->Init() failed with error 5` 直接挂（AMD 驱动 <23.30 不支持 10bit 编码）。
ENC_CANDIDATES: tuple[tuple[str, list], ...] = (
    ("h264_nvenc", ["-c:v", "h264_nvenc", "-preset", "p4", "-rc", "vbr"]),
    ("h264_amf",   ["-c:v", "h264_amf", "-quality", "speed"]),
    ("h264_qsv",   ["-c:v", "h264_qsv", "-preset", "veryfast"]),
    ("libx264",    ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency"]),
)
_ENC_BY_HEIGHT: dict[int, tuple[str, list]] = {}     # height -> (name, args) 实测通过的
_BAD_ENC: set[tuple[str, int]] = set()               # (name, height) 已实测证伪
_ENC_LOCK = threading.Lock()


def _probe_size(height: int) -> tuple[int, int]:
    """探针分辨率：按 16:9 算，宽高取偶数（yuv420p 要求）。"""
    return max(256, int(round(height * 16 / 9 / 2)) * 2), max(2, height // 2 * 2)


def _enc_works(args: list, height: int, bitrate: str) -> bool:
    """用**目标分辨率/码率**真跑几帧 —— 256x144 跑通 ≠ 4K 跑通。"""
    w, h = _probe_size(height)
    try:
        p = subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error",
             "-f", "lavfi", "-i", f"color=c=black:s={w}x{h}:r=25:d=0.2",
             "-vf", "format=yuv420p"] + args + ["-b:v", bitrate, "-f", "null", "-"],
            capture_output=True, timeout=60)
        if p.returncode != 0:
            tail = [l for l in (p.stderr or b"").decode("utf-8", "replace").splitlines() if l.strip()]
            if tail:
                print(f"[tc] 探针 {args[1]} @{height}p 失败: {tail[-1][:170]}")
        return p.returncode == 0
    except Exception:
        return False


def pick_encoder(height: int = 1080, bitrate: str | None = None,
                 skip: tuple = ()) -> tuple[str, list]:
    """挑一个**在该分辨率下实测可用**的 H.264 编码器（硬件优先，回落 libx264）。"""
    if height not in BITRATE:
        height = min(BITRATE, key=lambda k: abs(k - height))
    bitrate = bitrate or BITRATE.get(height, "6M")
    with _ENC_LOCK:
        hit = _ENC_BY_HEIGHT.get(height)
        if hit and hit[0] not in skip:
            return hit
        for name, args in ENC_CANDIDATES:
            if name in skip or (name, height) in _BAD_ENC:
                continue
            if not FFMPEG:                    # 没有 ffmpeg：只能报个名字，后面自然会失败
                return ENC_CANDIDATES[-1]
            if _enc_works(args, height, bitrate):
                _ENC_BY_HEIGHT[height] = (name, args)
                print(f"[tc] {height}p 编码器: {name}（已实测）")
                return name, args
            _BAD_ENC.add((name, height))
            print(f"[tc] {name} 在 {height}p 实测不可用，试下一个")
    return ENC_CANDIDATES[-1]


def mark_encoder_bad(name: str, height: int):
    """运行期翻车（首片没出来就退了）→ 拉黑，下次换人。"""
    with _ENC_LOCK:
        _BAD_ENC.add((name, height))
        if _ENC_BY_HEIGHT.get(height, ("",))[0] == name:
            _ENC_BY_HEIGHT.pop(height, None)


def enc_hint() -> str | None:
    """给 /api/health 用：已知用过的编码器名（不触发探针，避免健康检查变慢）。"""
    for h in (2160, 1440, 1080, 720, 480):
        if h in _ENC_BY_HEIGHT:
            return _ENC_BY_HEIGHT[h][0]
    return None


def _drop_session(sid: str):
    """结束一个转码会话：杀进程 + 删目录 + 清缓存映射。"""
    s = SESSIONS.pop(sid, None)
    if not s:
        return
    try:
        if s.get("proc") and s["proc"].poll() is None:
            s["proc"].kill()
            try:
                s["proc"].wait(timeout=3)      # ★ 等它真退出：kill 是异步的，
            except Exception:                  #   进程没走干净时文件句柄还没放开，
                pass                           #   rmtree 会删不干净（Windows 上会剩文件）
    except Exception:
        pass
    shutil.rmtree(s.get("dir", ""), ignore_errors=True)
    if s.get("key") and TC_BY_KEY.get(s["key"]) == sid:
        TC_BY_KEY.pop(s["key"], None)


def _cleanup_sessions(max_idle=1800):
    now = time.time()
    for sid, s in list(SESSIONS.items()):
        if now - s["last"] > max_idle:
            _drop_session(sid)


# ---------------------------------------------------------------- 缓存清理策略
# 都能用环境变量调：MYUKO_TC_IDLE / MYUKO_TC_SWEEP / MYUKO_TC_MAX_MB
TC_MAX_IDLE = int(os.environ.get("MYUKO_TC_IDLE", "1800"))    # 会话空闲多久回收（秒）
TC_SWEEP_SEC = int(os.environ.get("MYUKO_TC_SWEEP", "600"))   # 后台清扫间隔（秒）
TC_MAX_MB = int(os.environ.get("MYUKO_TC_MAX_MB", "8000"))    # 缓存总量上限（MB，0=不限）
TC_GRACE_START, TC_GRACE_TICK = 60, 120   # 启动/周期清扫时「多新的目录先别碰」（秒）


def _dir_mb(d: str) -> float:
    n = 0
    for root, _dirs, files in os.walk(d):
        for f in files:
            try:
                n += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return n / 1048576


def sweep_transcode_cache(reason: str = "定时", grace: int = TC_GRACE_TICK) -> str:
    """按目录 mtime 扫盘清理 TC_ROOT，返回一句摘要（没删东西就返回空串）。

    ★ 为什么不能只靠 `_cleanup_sessions`：
      1. 会话是用**内存里**的 SESSIONS / TC_BY_KEY 索引的 —— 服务一重启，磁盘上那些
         目录就再也不可能被命中，靠内存超时永远删不到它们（实测残留过 12 GB）；
      2. 它只在「下一次开转码」时被调用，不转码就永远不清理。
    """
    os.makedirs(TC_ROOT, exist_ok=True)
    now = time.time()
    killed = 0
    freed = 0.0
    for name in os.listdir(TC_ROOT):
        if name in SESSIONS:                 # 活跃会话交给 _cleanup_sessions 按 last 管
            continue
        d = os.path.join(TC_ROOT, name)
        if not os.path.isdir(d):
            continue
        try:
            if now - os.path.getmtime(d) < grace:    # 刚建的 / 可能正被别人写
                continue
        except OSError:
            continue
        freed += _dir_mb(d)
        shutil.rmtree(d, ignore_errors=True)
        killed += 1

    # 总量上限：超了就从「最久没人看」的会话开始丢（正在看的 last 很新，动不到它）
    dropped = 0
    if TC_MAX_MB > 0:
        total = sum(_dir_mb(os.path.join(TC_ROOT, n)) for n in os.listdir(TC_ROOT)
                    if os.path.isdir(os.path.join(TC_ROOT, n)))
        while total > TC_MAX_MB and SESSIONS:
            victim = min(SESSIONS.items(), key=lambda kv: kv[1]["last"])[0]
            if now - SESSIONS[victim]["last"] < 60:
                break
            total -= _dir_mb(SESSIONS[victim]["dir"])
            _drop_session(victim)
            dropped += 1

    if killed or dropped:
        msg = (f"[tc] 缓存清扫({reason})：删 {killed} 个残留目录 / {freed:.0f} MB"
               + (f"，超上限再丢 {dropped} 个会话" if dropped else ""))
        print(msg)
        return msg
    return ""


def _start_sweeper():
    """启动即扫一遍（清上一次运行的残留），之后每 TC_SWEEP_SEC 秒扫一次。"""
    def loop():
        try:
            sweep_transcode_cache("启动", TC_GRACE_START)
        except Exception as ex:
            print(f"[tc] 启动清扫失败: {ex}")
        while True:
            time.sleep(TC_SWEEP_SEC)
            try:
                _cleanup_sessions()
                sweep_transcode_cache("定时")
            except Exception as ex:
                print(f"[tc] 定时清扫失败: {ex}")
    threading.Thread(target=loop, daemon=True, name="tc-sweeper").start()


def _shutdown_children():
    """退出时把本进程起过的 ffmpeg 全带走，并删掉它们的转码目录。

    ★ 不这么做：Ctrl+C 只结束 python，ffmpeg 会变孤儿继续跑完整集、
      继续往 %TEMP% 里写 —— 「停止」之后磁盘还在涨（实测过一例）。
    """
    for sid in list(SESSIONS):
        _drop_session(sid)


def _log_tail(d: str, n: int = 320) -> str:
    """ffmpeg 日志最后几行 —— 失败原因要能一路报到前端，别只给个 404。"""
    try:
        with open(os.path.join(d, "ffmpeg.log"), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 6000))
            txt = fh.read().decode("utf-8", "replace")
    except Exception:
        return ""
    lines = [l.strip() for l in txt.splitlines() if l.strip()]
    return " | ".join(lines[-3:])[:n]


TC_FIRST_SEG_TIMEOUT = int(os.environ.get("MYUKO_TC_TIMEOUT", "40"))
SEEK_TOL = 8.0          # 缓存会话与请求起点的最大容差（超过就重开，让拖动生效）


def _await_first_segment(d: str, pl: str, proc, timeout: int | None = None):
    """等首片产出（或进程退出）。★ 进程秒退时必须立刻返回，不能干等到超时。"""
    t0 = time.time()
    limit = timeout or TC_FIRST_SEG_TIMEOUT
    while time.time() - t0 < limit:
        if os.path.exists(pl) and os.path.getsize(pl) > 0:
            return True, ""
        if proc.poll() is not None:
            time.sleep(0.3)                 # 等日志落盘
            if os.path.exists(pl) and os.path.getsize(pl) > 0:
                return True, ""
            return False, (_log_tail(d) or f"ffmpeg 退出码 {proc.returncode}")
        time.sleep(0.2)
    return False, f"等待首片超时（{limit}s）"


def _cached_session(key: str | None, start: float) -> dict | None:
    """缓存命中判断（起点接近才算命中）。"""
    if not key or key not in TC_BY_KEY:
        return None
    sid = TC_BY_KEY[key]
    s = SESSIONS.get(sid)
    if not (s and os.path.isdir(s["dir"]) and abs(s["start"] - start) <= SEEK_TOL):
        return None
    s["last"] = time.time()
    return {"sid": sid, "m3u8": f"/api/tc/playlist.m3u8?sid={sid}", "start": s["start"],
            "height": s["height"], "cached": True, "encoder": s.get("encoder")}


def _build_cmd(inp: str, enc_args: list, height: int, start: float,
               vbr: str, seg: str, pl: str) -> list:
    cmd = [FFMPEG, "-hide_banner", "-loglevel", "warning"]
    # ★ 必须把 httpproxy 放进来：显式指定 -protocol_whitelist 会**覆盖**默认值，
    #   而系统设了 http_proxy 时 ffmpeg 会走代理取 CDN，少了它直接打不开输入。
    WL = "file,http,https,tcp,tls,crypto,httpproxy"
    # ★ -allowed_extensions / -allowed_segment_extensions 是 **HLS demuxer 专属**选项，
    #   喂给 MP4 输入会直接报 `Option allowed_segment_extensions not found` 并退出。
    #   所以只在输入确实是 HLS 时才加。
    is_hls_in = ".m3u8" in inp.lower()
    cmd += ["-protocol_whitelist", WL]
    if is_hls_in:
        cmd += ["-allowed_extensions", "ALL",
                "-allowed_segment_extensions", "ALL"]
        # ★ 关键：ffmpeg 的 HLS demuxer 默认 `-extension_picky 1`，会按**整串 URL 最后一个点**
        #   判断扩展名。本站 CDN 的分片是 .png/.pdf 伪装的 MPEG-TS（或干脆没扩展名），
        #   于是被判 `detected format mpegts extension none mismatches allowed extensions`
        #   直接打不开。置 0 后 ffmpeg 不再纠结扩展名，按内容嗅探 —— 实测 4K HEVC
        #   分片直连可正常解码（14x 实时）。
        cmd += ["-extension_picky", "0"]
    if "://" in inp:                      # 网络输入才需要 UA
        cmd += ["-user_agent", "okhttp/3.12.1"]
    if start > 0:
        cmd += ["-ss", f"{start:.3f}"]
    # ★ 缩放必须写成 min(目标高, 源高)，不能直接 scale=-2:目标高：
    #   ① 宽幅源会把宽度算爆 —— 实测源 3840x1598（2.40:1）配 scale=-2:2160 得到
    #      5190x2160，超过 AMD 编码器 4096 的最大宽度 → `encoder->Init() failed
    #      with error 5`，整个 4K 转码直接失败（换成 16:9 的 3840x2160 源就没事）；
    #   ② 小源也不该被拉大（1080p 源点「转码 4K」没必要烧 CPU 做无意义放大）。
    #   后面再补 format=yuv420p：10bit 源（HEVC Main10）解出来是 p010，
    #   硬件编码器（尤其 AMD 老驱动）同样会 init 失败；补上就回落 8bit。
    cmd += ["-i", inp] + enc_args + [
            "-b:v", vbr, "-maxrate", vbr, "-bufsize", "24M",
            "-vf", f"scale=-2:'min({height},ih)',format=yuv420p",
            "-c:a", "copy",                      # 音频不重编，省一半时间
            "-f", "hls", "-hls_time", "4", "-hls_playlist_type", "event",
            "-hls_list_size", "0", "-hls_flags", "independent_segments",
            "-hls_segment_filename", seg, pl]
    return cmd



def prepare_local_playlist(src: str, workdir: str) -> str:
    """把远端 m3u8 抓下来，重写成带扩展名的本地代理链接，落盘给 ffmpeg 用。

    原因：ffmpeg 的 HLS demuxer 会拒绝「没有已知扩展名」的分片 URL
    （`not in allowed_segment_extensions`），而本站的 CDN 分片恰恰没有扩展名。
    走本机代理 + 补上 .ts/.key 后缀可彻底绕开该限制。
    """
    st, raw, _ = fetch(src, {"User-Agent": "okhttp/3.12.1"})
    text = raw.decode("utf-8", "replace")
    if not text.lstrip().startswith("#EXTM3U"):
        return src
    learn_m3u8_hosts(text, src)      # ★ 分片域名先进白名单，否则下面本地代理全 403
    tok = ("&k=" + ACCESS_TOKEN) if ACCESS_TOKEN else ""
    n = 0

    def local(u: str, ext: str) -> str:
        nonlocal n
        n += 1
        absu = urllib.parse.urljoin(src, u)
        return (f"http://127.0.0.1:{PORT}/api/seg/part{n:05d}{ext}"
                f"?u={urllib.parse.quote(absu, safe='')}{tok}")

    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            out.append(line)
        elif s.startswith("#"):
            if 'URI="' in s:
                pre, _, rest = s.partition('URI="')
                uri, _, post = rest.partition('"')
                out.append(f'{pre}URI="{local(uri, ".key")}"{post}')
            else:
                out.append(line)
        else:
            out.append(local(s, ".ts"))
    path = os.path.join(workdir, "source.m3u8")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    return path


def start_transcode(src: str, start: float = 0.0, height: int = 1080,
                    key: str | None = None) -> dict:
    """启动（或复用）ffmpeg 把 src 实时转成 H.264 HLS，返回 {sid, m3u8, cached}。

    ★ 会「实测首片 + 失败自动换编码器重试」：硬件编码器往往只在小尺寸下能跑，
      遇到 4K 宽幅源（宽度超上限）或 10bit 源就会 init 失败。
    """
    if not FFMPEG:
        raise RuntimeError("未找到 ffmpeg，无法转码")
    vbr = BITRATE.get(height, "6M")
    with TC_LOCK:
        _cleanup_sessions()
        hit = _cached_session(key, start)      # 命中同集同高度且起点相近 → 重看不重转
        if hit:
            return hit
        if key and key in TC_BY_KEY:           # 有映射但起点差太多/会话已死 → 丢掉重开
            _drop_session(TC_BY_KEY[key])
        if len(SESSIONS) >= MAX_TRANSCODES:
            raise RuntimeError(f"转码会话已满（上限 {MAX_TRANSCODES}），请稍后再试")

        os.makedirs(TC_ROOT, exist_ok=True)
        tried: list[str] = []
        last_err = ""
        for _ in range(len(ENC_CANDIDATES)):
            enc_name, enc_args = pick_encoder(height, vbr, skip=tuple(tried))
            if enc_name in tried:
                break                          # 候选都试过了
            tried.append(enc_name)
            sid = uuid.uuid4().hex[:12]
            d = os.path.join(TC_ROOT, sid)
            os.makedirs(d, exist_ok=True)
            inp = src
            if ".m3u8" in src.lower():
                try:
                    inp = prepare_local_playlist(src, d)
                except Exception as ex:
                    print(f"[tc] 本地化 m3u8 失败，直接用原链: {ex}")
            seg = os.path.join(d, "seg%05d.ts")
            pl = os.path.join(d, "index.m3u8")
            logf = open(os.path.join(d, "ffmpeg.log"), "wb")
            proc = subprocess.Popen(
                _build_cmd(inp, enc_args, height, start, vbr, seg, pl),
                stdout=subprocess.DEVNULL, stderr=logf,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            logf.close()                       # 子进程已 dup，父进程这份不用留
            ok, err = _await_first_segment(d, pl, proc)
            if ok:
                SESSIONS[sid] = {"dir": d, "proc": proc, "last": time.time(), "src": src,
                                 "start": start, "height": height, "key": key,
                                 "encoder": enc_name}
                if key:
                    TC_BY_KEY[key] = sid
                return {"sid": sid, "m3u8": f"/api/tc/playlist.m3u8?sid={sid}",
                        "start": start, "height": height, "cached": False,
                        "encoder": enc_name, "bitrate": vbr, "localized": inp != src,
                        "tried": tried}
            # ---- 失败：清理现场 + 把这个编码器拉黑，换下一个再试 ----
            last_err = err
            print(f"[tc] {enc_name} 转码失败（{err}），换编码器重试")
            mark_encoder_bad(enc_name, height)
            try:
                proc.kill()
            except Exception:
                pass
            shutil.rmtree(d, ignore_errors=True)
        raise RuntimeError(f"转码失败（已试 {'→'.join(tried) or '无可用编码器'}）：{last_err}")


def tc_playlist(sid: str):
    """成功 → bytes；失败 → 字符串原因（顺带把死会话清掉，下次 /api/tc 才能重开）。"""
    s = SESSIONS.get(sid)
    if not s:
        return "转码会话不存在（可能已被回收），请重新点「转码播放」"
    s["last"] = time.time()
    pl = os.path.join(s["dir"], "index.m3u8")
    for _ in range(80):                     # 等首片生成（最长 ~20s）
        if os.path.exists(pl) and os.path.getsize(pl) > 0:
            break
        if s["proc"].poll() is not None and not os.path.exists(pl):
            err = _log_tail(s["dir"])
            _drop_session(sid)              # 死的会话立刻回收，否则永远 404
            return f"转码进程已退出：{err}" if err else "转码进程已退出"
        time.sleep(0.25)
    if not os.path.exists(pl):
        return "转码首片未生成（超时），请重试"
    txt = open(pl, encoding="utf-8", errors="replace").read()
    out = []
    for line in txt.splitlines():
        if line and not line.startswith("#"):
            out.append(f"/api/tc/seg?sid={sid}&f={line.strip()}")
        else:
            out.append(line)
    return ("\n".join(out) + "\n").encode("utf-8")


def tc_segment(sid: str, fname: str):
    s = SESSIONS.get(sid)
    if not s:
        return None
    s["last"] = time.time()
    fname = os.path.basename(fname)
    path = os.path.join(s["dir"], fname)
    for _ in range(200):                    # 等该片转出来
        if os.path.exists(path) and os.path.getsize(path) > 0:
            time.sleep(0.05)
            with open(path, "rb") as fh:
                return fh.read()
        if s["proc"].poll() is not None:
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    return fh.read()
            return None
        time.sleep(0.25)
    return None




def api_proxy_img(q):
    u = q.get("u", [""])[0]
    if not u:
        return None
    if not host_allowed(u):
        return None
    try:
        _, raw, hdrs = fetch(u, {"Referer": "/".join(u.split("/")[:3]) + "/"})
        return raw, hdrs.get("Content-Type") or "image/jpeg"
    except Exception:
        # 占位图
        svg = (b'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="320">'
               b'<rect width="240" height="320" fill="#22262e"/>'
               b'<text x="120" y="165" fill="#666" font-size="14" text-anchor="middle">'
               b'no cover</text></svg>')
        return svg, "image/svg+xml"


# --------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "MyukoWeb/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, code, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        nv = getattr(self, "new_visitor", None)
        if nv:
            self.send_header("Set-Cookie",
                             f"myuko_v={nv}; Path=/; SameSite=Lax; Max-Age=31536000")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        # ★ HEAD 请求只回头不回体（浏览器预览、监控、链接检查都会先发 HEAD，
        #   不处理会返回 501 被判成「站点挂了」）
        if getattr(self, "_head_only", False):
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def do_HEAD(self):
        """HEAD = GET 的头部，不带 body。"""
        self._head_only = True
        self.do_GET()

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _stream(self, u: str, direct: bool = False):
        """流式转发（支持 Range），用于直连 MP4 / HLS 分片。"""
        if not host_allowed(u):
            return self._json({"ok": False, "msg": "目标域名不在白名单内"}, 403)
        rng = self.headers.get("Range")
        try:
            up = open_upstream(u, rng)
        except urllib.error.HTTPError as ex:
            if ex.code in (416, 200, 206):
                up = ex
            else:
                return self._json({"ok": False, "msg": f"upstream {ex.code}"}, 502)
        ctype = up.headers.get("Content-Type") or "application/octet-stream"
        if u.split("?")[0].endswith(".m3u8") or "mpegurl" in ctype:
            raw = up.read()
            body = rewrite_m3u8(raw.decode("utf-8", "replace"), u, direct=direct).encode("utf-8")
            return self._send(200, body, "application/vnd.apple.mpegurl")
        self.send_response(up.status)
        self.send_header("Content-Type", ctype)
        for k in ("Content-Length", "Content-Range", "Accept-Ranges"):
            v = up.headers.get(k)
            if v:
                self.send_header(k, v)
        if not up.headers.get("Accept-Ranges"):
            self.send_header("Accept-Ranges", "bytes")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if getattr(self, "_head_only", False):      # HEAD 不回体
            try:
                up.close()
            except Exception:
                pass
            return
        try:
            while True:
                chunk = up.read(262144)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass
        finally:
            try:
                up.close()
            except Exception:
                pass

    def _authed(self, q) -> bool:
        """令牌校验：?k=<token> 优先（顺便种 Cookie），否则读 Cookie / X-Auth。"""
        if not ACCESS_TOKEN:
            return True
        tok = (q.get("k", [""])[0]
               or self.headers.get("X-Auth")
               or self.headers.get("Authorization", "").replace("Bearer ", ""))
        if not tok:
            for part in (self.headers.get("Cookie") or "").split(";"):
                if part.strip().startswith("myuko_k="):
                    tok = part.strip()[8:]
                    break
        return bool(tok) and hmac_compare(tok, ACCESS_TOKEN)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)
        ip = client_ip(self)
        # ---- 访客标识（用于分配设备池中的身份）----
        visitor = ""
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("myuko_v="):
                visitor = part[8:]
                break
        if not visitor:
            visitor = secrets.token_hex(8)
            self.new_visitor = visitor
        set_visitor(visitor)
        try:
            # ---- 鉴权 ----
            if not self._authed(q):
                # 浏览器直接打开 → 给一个友好的取 token 页面，而不是裸 JSON
                if "text/html" in (self.headers.get("Accept") or ""):
                    return self._send(401, LOGIN_HTML.encode("utf-8"),
                                      "text/html; charset=utf-8")
                return self._json({"ok": False, "msg": "未授权：请在 URL 后加 ?k=<token>"}, 401)
            # 只有「页面」请求才把 ?k= 换成 Cookie（API/代理请求带 k= 直接放行，不能重定向）
            if q.get("k") and p.path in ("/", "/index.html"):
                return self._send(302, b"", "text/plain",
                                  {"Location": "/",
                                   "Set-Cookie": f"myuko_k={ACCESS_TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"})
            # ---- 限流 ----
            if not rate_ok(ip, p.path):
                return self._json({"ok": False, "msg": "请求过于频繁，请稍后再试"}, 429)

            if p.path in ("/", "/index.html"):
                return self._send(200, INDEX_HTML.encode("utf-8"),
                                  "text/html; charset=utf-8")
            if p.path == "/favicon.ico":
                return self._send(200, FAVICON, "image/svg+xml",
                                  {"Cache-Control": "max-age=86400"})
            if p.path == "/hls.min.js":
                # ★ 本地提供 hls.js —— 外网 CDN 可能被墙/超时（实测 jsdelivr 会 EOF），
                #   加载失败会导致 HLS 完全播不了（表现为「播放中但没有画面」）。
                try:
                    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "hls.min.js"), "rb") as fh:
                        js = fh.read()
                    return self._send(200, js, "application/javascript; charset=utf-8",
                                      {"Cache-Control": "max-age=86400"})
                except Exception:
                    return self._json({"ok": False, "msg": "hls.min.js 缺失"}, 404)
            if p.path == "/api/health":
                pool = _ensure_pool()
                enc = enc_hint() if FFMPEG else None
                return self._json({"ok": True,
                                   "slot": __import__("magic_v3").slot_of(int(time.time())),
                                   "devices": len(pool), "transcodes": len(SESSIONS),
                                   "auth": bool(ACCESS_TOKEN), "mode": "direct",
                                   "ffmpeg": bool(FFMPEG), "encoder": enc})
            if p.path == "/api/search":
                return self._json(api_search(q))
            if p.path == "/api/detail":
                return self._json(api_detail(q))
            if p.path == "/api/episodes":
                return self._json(api_episodes(q))
            if p.path == "/api/play":
                return self._json(api_play(q))
            if p.path == "/api/seg" or p.path.startswith("/api/seg/"):
                u = q.get("u", [""])[0]
                if not u:
                    return self._json({"ok": False, "msg": "缺少 u"}, 400)
                return self._stream(u, direct=(q.get("direct", ["0"])[0] == "1"))
            if p.path == "/api/kazumi/chapters":
                _host = self.headers.get("Host") or ""
                _scheme = "https" if (self.headers.get("X-Forwarded-Proto") or "").lower() == "https" else "http"
                return self._json(api_kazumi_chapters(q, host=_host, scheme=_scheme))
            if p.path == "/api/kazumi/qualities":
                return self._json(api_kazumi_qualities(q))
            if p.path == "/api/kazumi/play.m3u8":
                r = api_kazumi_play(q)
                if not r.get("ok"):
                    return self._json(r, 502)
                # MP4 直链 → 302（浏览器/播放器直连 CDN，不经本机）
                if r.get("kind") == "mp4":
                    self.send_response(302)
                    self.send_header("Location", r["url"])
                    self.end_headers()
                    return
                # HLS → 回重写后的 m3u8，Content-Type 必须是 mpegurl，
                # 且 URL 以 .m3u8 结尾，Kazumi 才能当"已是媒体地址"直接播
                return self._stream(r["url"], direct=True)
            if p.path == "/api/m3u8":
                u = q.get("u", [""])[0]
                if not u:
                    return self._json({"ok": False, "msg": "缺少 u"}, 400)
                return self._stream(u, direct=(q.get("direct", ["0"])[0] == "1"))
            if p.path == "/api/tc":                     # 启动/复用转码会话
                vid = q.get("videoId", [""])[0]
                code = q.get("code", [""])[0]
                ep = int(q.get("ep", ["1"])[0] or 1)
                h = int(q.get("h", ["1080"])[0] or 1080)
                start = float(q.get("start", ["0"])[0] or 0)
                u = q.get("u", [""])[0]
                key = f"{vid}|{code}|{ep}|{h}" if (vid and code) else None
                try:
                    # ① 缓存命中（同集 + 同高度 + 起点相近）→ 直接复用，此时不需要 u
                    hit = _cached_session(key, start)
                    if hit:
                        return self._json({"ok": True, **hit})
                    # ② 没给 u 但有 videoId → 服务端自己解析播放地址
                    if not u and key:
                        urls = learn_hosts(with_retry(lambda c: c.play(vid, code, ep)))
                        if not urls:
                            return self._json({"ok": False, "msg": "未取到播放地址"})
                        u = pick_source_for_height(urls, h)["url"]
                    if not u:
                        return self._json({"ok": False, "msg": "缺少 u 或 videoId/code"}, 400)
                    if not host_allowed(u):
                        return self._json({"ok": False, "msg": "目标域名不在白名单内"}, 403)
                    info = start_transcode(u, start, h, key)
                except Exception as ex:
                    return self._json({"ok": False, "msg": str(ex)})
                return self._json({"ok": True, **info})
            if p.path == "/api/tc/playlist.m3u8":
                r = tc_playlist(q.get("sid", [""])[0])
                if isinstance(r, bytes):
                    return self._send(200, r, "application/vnd.apple.mpegurl")
                return self._json({"ok": False, "msg": r}, 404)
            if p.path == "/api/tc/seg":
                body = tc_segment(q.get("sid", [""])[0], q.get("f", [""])[0])
                return self._send(200, body, "video/mp2t") if body \
                    else self._json({"ok": False, "msg": "分片未就绪"}, 404)
            if p.path == "/api/img":
                r = api_proxy_img(q)
                return self._send(200, r[0], r[1]) if r else self._json({"ok": False}, 400)
            self._json({"ok": False, "msg": "not found"}, 404)
        except Exception as ex:
            traceback.print_exc()
            self._json({"ok": False, "msg": f"{type(ex).__name__}: {ex}"}, 500)


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>测试·某动漫</title>
<link rel="icon" href="/favicon.ico">
<script src="/hls.min.js"></script>
<script>
// 本地 hls.js 拿不到时回退 CDN（双保险）
if(!window.Hls){ document.write('<script src="https://unpkg.com/hls.js@1.5.20/dist/hls.min.js"><\/script>'); }
</script>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0f1115;color:#e6e8ee;font:14px/1.6 "Segoe UI","Microsoft YaHei",sans-serif}
  a{color:inherit}
  header{position:sticky;top:0;z-index:20;background:rgba(15,17,21,.92);backdrop-filter:blur(8px);
         border-bottom:1px solid #232833;padding:12px 20px;display:flex;gap:12px;align-items:center}
  .logo{font-size:17px;font-weight:700;color:#4ea1ff;white-space:nowrap}
  .search{flex:1;display:flex;gap:8px;max-width:640px}
  input[type=text]{flex:1;background:#181c24;border:1px solid #2b3240;border-radius:8px;
                   padding:9px 13px;color:#e6e8ee;font-size:14px;outline:none}
  input[type=text]:focus{border-color:#4ea1ff}
  button{background:#2a6fd6;border:0;color:#fff;border-radius:8px;padding:9px 18px;
         cursor:pointer;font-size:14px}
  button:hover{background:#3a80e8}
  button.ghost{background:#232833}
  button.ghost:hover{background:#2e3542}
  main{padding:20px}
  #status{color:#8b93a3;padding:6px 0 14px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:16px}
  .card{background:#171b22;border:1px solid #232833;border-radius:10px;overflow:hidden;
        cursor:pointer;transition:.15s;display:flex;flex-direction:column}
  .card:hover{transform:translateY(-3px);border-color:#4ea1ff;box-shadow:0 8px 24px #0008}
  .card img{width:100%;aspect-ratio:3/4;object-fit:cover;background:#22262e;display:block}
  .card .meta{padding:8px 10px}
  .card .t{font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .card .s{font-size:12px;color:#8b93a3;display:flex;gap:8px;margin-top:2px}
  .card .s .score{color:#ffb400}
  #view{display:none;gap:22px;grid-template-columns:260px 1fr}
  #view.on{display:grid}
  #view .poster{width:100%;border-radius:10px;aspect-ratio:3/4;object-fit:cover;background:#22262e}
  .info h2{font-size:22px;margin-bottom:8px}
  .chips{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
  .chip{background:#232833;border-radius:20px;padding:2px 11px;font-size:12px;color:#a9b2c3}
  .desc{color:#9aa3b3;font-size:13px;max-height:110px;overflow:auto;margin:10px 0}
  .players{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
  .pl{background:#232833;border:1px solid #2b3240;border-radius:8px;padding:6px 14px;cursor:pointer}
  .pl.on{background:#2a6fd6;border-color:#2a6fd6}
  .eps{display:grid;grid-template-columns:repeat(auto-fill,minmax(78px,1fr));gap:8px;
       max-height:230px;overflow:auto;padding:4px;border:1px solid #232833;border-radius:10px;background:#141821}
  .ep{background:#1e232d;border:1px solid #2b3240;border-radius:7px;padding:7px 4px;
      text-align:center;font-size:12.5px;cursor:pointer;white-space:nowrap;overflow:hidden}
  .ep:hover{background:#2a6fd6;border-color:#2a6fd6}
  .ep.on{background:#2a6fd6;border-color:#2a6fd6;font-weight:700}
  #playerWrap{display:none;margin-top:16px}
  #playerWrap.on{display:block}
  video{width:100%;max-height:66vh;background:#000;border-radius:10px;display:block}
  #now{color:#8b93a3;font-size:13px;margin:8px 0}
  #hint{color:#c9a227;font-size:13px;line-height:1.9;margin-bottom:4px}
  #hint a{color:#4ea1ff;text-decoration:none;margin-right:12px}
  #hint a:hover{text-decoration:underline}
  #banner{background:#1b1f2a;border-bottom:1px solid #2b3240;padding:10px 20px;
          font-size:13px;color:#a9b2c3;line-height:1.9}
  #banner b{color:#ffd54f}
  #banner a{color:#4ea1ff;text-decoration:none}
  #banner a:hover{text-decoration:underline}
  #banner .off{color:#6b7484;margin-left:10px}
  #banner.hide{display:none}
  .spinner{display:inline-block;width:13px;height:13px;border:2px solid #4ea1ff;
           border-top-color:transparent;border-radius:50%;animation:sp .7s linear infinite;
           vertical-align:-2px;margin-right:6px}
  @keyframes sp{to{transform:rotate(360deg)}}
  .back{margin-bottom:14px}
</style>
</head>
<body>
<header>
  <div class="logo">测试•某动漫</div>
  <div class="search">
    <input id="kw" type="text" placeholder="搜索番剧 / 电影，回车或点搜索" autofocus>
    <button onclick="doSearch()">搜索</button>
  </div>
  <button class="ghost" onclick="goHome()">首页</button>
</header>
<div id="banner">
  <b>关于 4K 画质</b>：4K 档是 <b>H.265 / HEVC</b> 编码，浏览器需要系统级解码支持。
  <b>Windows</b> 装「HEVC 视频扩展」即可 →
  <a href="https://apps.microsoft.com/detail/9n4wgh0z6vhq" target="_blank">免费版</a>
  <a href="https://apps.microsoft.com/detail/9nmzlz57r3t7" target="_blank">官方版（¥7）</a>
  <a href="ms-windows-store://pdp/?productid=9N4WGH0Z6VHQ">在商店中打开</a>
  ｜ <b>macOS / iOS / 多数 Android</b> 原生支持，无需安装。<br>
  <span style="color:#8b93a3">注意：<b>MP4 封装</b>的 4K 装扩展即可播放；
  <b>HLS 封装</b>的 4K 浏览器无法直接播（MSE 不支持 HEVC），会自动切到 1080P H264 ——
  想看这种 4K 得用<b>服务器转码</b>（需服务器已装 ffmpeg）。</span>
  <a href="#" class="off" onclick="dismissBanner();return false">不再提示</a>
</div>
<main>
  <div id="status">输入关键词开始搜索</div>
  <div id="grid" class="grid"></div>
  <div id="view">
    <div><img id="poster" class="poster" alt=""></div>
    <div class="info">
      <h2 id="vtitle"></h2>
      <div class="chips" id="vchips"></div>
      <div class="desc" id="vdesc"></div>
      <div class="players" id="vplayers"></div>
      <div id="eplabel" style="color:#8b93a3;font-size:13px;margin-bottom:6px"></div>
      <div class="eps" id="veps"></div>
      <div id="playerWrap">
        <div class="players" id="vquality"></div>
        <video id="video" controls playsinline crossorigin="anonymous"></video>
        <div id="now"></div>
        <div id="hint"></div>
      </div>
    </div>
  </div>
</main>
<script>
const $ = s => document.querySelector(s);
const img = u => u ? '/api/img?u=' + encodeURIComponent(u) : '';
let cur = null, hls = null;
// 浏览器是否支持 HEVC(H.265) 硬解
const HEVC_OK = (() => {
  const v = document.createElement('video');
  return !!(v.canPlayType('video/mp4; codecs="hvc1.1.6.L153.B0"') ||
            v.canPlayType('video/mp4; codecs="hev1.1.6.L153.B0"'));
})();
// 4K 提示横幅（可关闭，记住选择）
function dismissBanner(){
  try{ localStorage.setItem('myuko_banner','off'); }catch(e){}
  document.getElementById('banner').classList.add('hide');
}
try{ if(localStorage.getItem('myuko_banner')==='off')
       document.getElementById('banner').classList.add('hide'); }catch(e){}
// 记住「本浏览器播不了 HLS 封装的 HEVC」——避免每次都白等 8 秒解码校验
function hlsHevcBad(){ try{ return localStorage.getItem('myuko_hlshevc_bad')==='1'; }catch(e){ return false; } }
function markHlsHevcBad(){ try{ localStorage.setItem('myuko_hlshevc_bad','1'); }catch(e){} }
function clearHlsHevcBad(){ try{ localStorage.removeItem('myuko_hlshevc_bad'); }catch(e){} }
// ---- 播放进度记忆（192 集，没这个很难受）----
const posKey = (vid, ep) => 'myuko_pos_' + vid + '_' + ep;
function fmtTime(s){ s=Math.floor(s||0); const m=Math.floor(s/60); return m + ':' + String(s%60).padStart(2,'0'); }
function getPos(vid, ep){ try{ return parseInt(localStorage.getItem(posKey(vid,ep))||'0',10) || 0; }catch(e){ return 0; } }
function setPos(vid, ep, t){ try{ localStorage.setItem(posKey(vid,ep), String(Math.floor(t))); }catch(e){} }
function clearPos(vid, ep){ try{ localStorage.removeItem(posKey(vid,ep)); }catch(e){} }
// 每 5 秒存一次进度（只在真正播放时）
setInterval(() => {
  const v = document.querySelector('#video');
  if(!cur || !cur.ep || !v || v.paused || !isFinite(v.duration)) return;
  if(v.currentTime > 15 && v.currentTime < v.duration - 20) setPos(cur.id, cur.ep, v.currentTime);
}, 5000);

async function jget(u){ const r = await fetch(u); return await r.json(); }

// 服务器能力探测（ffmpeg 有没有 → 决定转码时提示装什么依赖）
let SYS = { ffmpeg: null, encoder: null };
(async () => { try{ SYS = await jget('/api/health'); }catch(e){} })();

function setStatus(html){ $('#status').innerHTML = html; }

async function doSearch(){
  const kw = $('#kw').value.trim(); if(!kw) return;
  setStatus('<span class="spinner"></span>搜索中…');
  $('#view').classList.remove('on'); $('#grid').style.display='grid';
  try{
    const d = await jget('/api/search?keyword=' + encodeURIComponent(kw) + '&size=24');
    if(!d.ok){ setStatus('搜索失败：' + (d.msg||'')); return; }
    if(!d.count){ setStatus('没有找到结果'); $('#grid').innerHTML=''; return; }
    setStatus('共 ' + d.count + ' 条结果');
    $('#grid').innerHTML = d.items.map(v => `
      <div class="card" onclick="openDetail('${v.id}')">
        <img loading="lazy" src="${img(v.cover)}" alt="">
        <div class="meta">
          <div class="t" title="${esc(v.title)}">${esc(v.title)}</div>
          <div class="s"><span>${v.year||''}</span>
            ${v.score?`<span class="score">★ ${v.score}</span>`:''}
            <span>${esc((v.custom||'').slice(0,10))}</span></div>
        </div>
      </div>`).join('');
  }catch(e){ setStatus('搜索异常：' + e); }
}

function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function goHome(){
  $('#view').classList.remove('on'); $('#grid').style.display='grid';
  $('#playerWrap').classList.remove('on');
  if(hls){ hls.destroy(); hls=null; }
  $('#video').removeAttribute('src'); $('#video').load();
  setStatus('输入关键词开始搜索');
}

async function openDetail(id){
  cur = {id}; setStatus('<span class="spinner"></span>加载详情…');
  $('#grid').style.display='none'; $('#view').classList.add('on');
  $('#playerWrap').classList.remove('on');
  if(hls){ hls.destroy(); hls=null; }
  const d = await jget('/api/detail?videoId=' + id);
  if(!d.ok){ setStatus('详情失败：' + (d.msg||'')); return; }
  const v = d.video; cur.v = v;
  $('#poster').src = img(v.cover);
  $('#vtitle').textContent = v.title;
  $('#vchips').innerHTML = [v.year, v.area, v.score?('★ '+v.score):'',
      (v.currentEpisodes?('更新至 '+v.currentEpisodes):''),
      (v.isFinished?'已完结':'连载中')]
      .filter(Boolean).map(x=>`<span class="chip">${esc(x)}</span>`).join('')
    + (v.tags||'').split(',').filter(Boolean).slice(0,8)
      .map(t=>`<span class="chip">${esc(t)}</span>`).join('');
  $('#vdesc').innerHTML = (v.description||'').replace(/&nbsp;/g,' ');
  const players = v.players && v.players.length ? v.players : [{playerCode:'cn',playerName:'默认'}];
  cur.code = players[0].playerCode;
  $('#vplayers').innerHTML = players.map((p,i)=>
    `<div class="pl ${i===0?'on':''}" onclick="pickPlayer(this,'${p.playerCode}')">
       ${esc(p.playerName||p.playerCode)}</div>`).join('');
  await loadEps();
}

function pickPlayer(el, code){
  document.querySelectorAll('.pl').forEach(x=>x.classList.remove('on'));
  el.classList.add('on'); cur.code = code; loadEps();
}

async function loadEps(){
  setStatus('<span class="spinner"></span>加载剧集…');
  const d = await jget(`/api/episodes?videoId=${cur.id}&code=${encodeURIComponent(cur.code)}`);
  if(!d.ok){ $('#eplabel').textContent='剧集加载失败：'+(d.msg||''); return; }
  $('#eplabel').textContent = `剧集（${d.count}）— 点击即播放`;
  setStatus('');
  $('#veps').innerHTML = d.episodes.map(e =>
    `<div class="ep" data-n="${e.n}" onclick="playEp(this,${e.n})">${esc(e.name||('第'+e.n+'集'))}</div>`).join('');
  if(d.count) playEp($('#veps').firstElementChild, d.episodes[0].n);
}

async function playEp(el, n){
  document.querySelectorAll('.ep').forEach(x=>x.classList.remove('on'));
  if(el) el.classList.add('on');
  $('#playerWrap').classList.add('on');
  $('#vquality').innerHTML = '';
  $('#hint').innerHTML = '';
  $('#now').innerHTML = '<span class="spinner"></span>解析播放地址…';
  const d = await jget(`/api/play?videoId=${cur.id}&code=${encodeURIComponent(cur.code)}&ep=${n}`);
  if(!d.ok){ $('#now').textContent = '解析失败：' + (d.msg||''); return; }
  cur.opts = d.all || [d.play];
  cur.ep = n;
  cur.resumed = false;
  $('#vquality').innerHTML = cur.opts.map((o,i)=>
    `<div class="pl" onclick="pickQuality(this,${i})">${esc(o.quality||'')} ${esc(o.vcodec||'')}</div>`).join('');
  // ★ 默认挑一个**非 HEVC** 的档（H.264 任何浏览器都能播）。
  //   不用 canPlayType 判断 —— 手机浏览器会误报支持 HEVC，反而选中播不了的档。
  let pick = cur.opts.findIndex(o => !isHevc(o));
  if(pick < 0) pick = 0;                    // 全都是 HEVC → 只能靠转码
  const btns = document.querySelectorAll('#vquality .pl');
  if(btns[pick]) btns[pick].classList.add('on');
  playUrl(cur.opts[pick]);
}

function isHevc(o){ return /26[56]|hevc/i.test(o.vcodec || ''); }

function showTranscode(msg, o){
  // ★ HLS 封装的 HEVC：装浏览器扩展**没用**，别再误导 —— 只提示「需要服务器转码」，
  //   并检查服务器有没有 ffmpeg；缺了就告诉用户装什么。
  const hlsHevc = o && o.kind === 'hls' && isHevc(o);
  if(hlsHevc){
    if(SYS.ffmpeg === false){          // 服务器没装 ffmpeg
      $('#hint').innerHTML =
        `⚠ 这一集的 4K 是 <b>HLS 封装的 HEVC</b>，浏览器播不了，只能靠<b>服务器转码</b>。<br>`
        + `但服务器上<b>没检测到 ffmpeg</b>。装上后重启服务即可：<br>`
        + `<code style="background:#11151c;border:1px solid #2b3240;border-radius:5px;`
        + `padding:1px 6px;color:#9fb6d6">winget install Gyan.FFmpeg</code>`
        + `<a href="https://www.gyan.dev/ffmpeg/builds/" target="_blank">下载页</a>`
        + (o ? `<a href="${o.direct}" target="_blank">直链下载</a>` : '');
      $('#now').innerHTML = `已自动切回 <b>1080P H264</b>（无需任何扩展）。`;
      return;
    }
    // ffmpeg 可用（或还没探测出来）→ 直接给转码入口，不再提扩展
    $('#hint').innerHTML =
      `⚠ 这一集的 4K 是 <b>HLS 封装的 HEVC</b>，浏览器无法直接播放，需走服务器转码`
      + (SYS.encoder ? `（编码器 <b>${esc(SYS.encoder)}</b>）` : '') + `：<br>`
      + `<a href="#" onclick="doTranscode(2160);return false">▶ 转码播放 4K</a>`
      + `<a href="#" onclick="doTranscode(1080);return false">▶ 转码播放 1080P</a>`
      + (o ? `<a href="${o.direct}" target="_blank">直链下载</a>` : '')
      + `<a href="#" onclick="clearHlsHevcBad();playUrl(cur.cur,0,1);return false" `
      + `style="color:#6b7484">仍然尝试直接播</a>`;
    $('#now').innerHTML = `已自动切回 <b>1080P H264</b>（无需任何扩展）。`
      + (SYS.ffmpeg ? `想看 4K 请点上面的「转码播放 4K」。` : '');
    return;
  }
  // MP4 封装的 HEVC：装系统扩展**确实能解决** → 给扩展链接
  $('#hint').innerHTML = `4K 需要 HEVC 解码支持：`
    + `<a href="https://apps.microsoft.com/detail/9n4wgh0z6vhq" target="_blank">免费版扩展</a>`
    + `<a href="https://apps.microsoft.com/detail/9nmzlz57r3t7" target="_blank">官方版(¥7)</a>`
    + (o ? `<a href="${o.direct}" target="_blank">直链下载</a>` : '');
  $('#now').innerHTML = `${msg ? esc(msg) + ' ' : ''}`
    + `装好扩展后刷新页面即可播放；或改选 <b>1080P H264</b> 档。`;
}

// 自动降档：在 #hint 里留下可操作的提示，而不是一闪而过
function switchTo(i, why){
  const btns = document.querySelectorAll('#vquality .pl');
  btns.forEach(x=>x.classList.remove('on'));
  if(btns[i]) btns[i].classList.add('on');
  const o = cur.opts[i];
  const badIdx = cur.opts.findIndex(x => isHevc(x));
  let h = `⚠ ${esc(why)}，已自动切到 <b>${esc(o.quality||'')} ${esc(o.vcodec||'')}</b>。`;
  if(badIdx >= 0){
    h += `<a href="#" onclick="playUrl(cur.opts[${badIdx}],0,1);return false">仍然尝试 HEVC</a>`;
    h += `<a href="#" onclick="cur.cur=cur.opts[${badIdx}];doTranscode();return false" `
       + `style="color:#6b7484">用服务器转码（消耗服务器带宽，不推荐）</a>`;
  }
  $('#hint').innerHTML = h;
  $('#now').textContent = '';
  setTimeout(()=>playUrl(o), 300);
}

function pickQuality(el, i){
  document.querySelectorAll('#vquality .pl').forEach(x=>x.classList.remove('on'));
  el.classList.add('on');
  const o = cur.opts[i];
  // 已在转码模式、又点了 HEVC 档 → 直接按该档对应高度重开转码（别退回普通播放把转码弄丢）
  if(cur.tcHeight && isHevc(o)){
    cur.cur = o;
    return doTranscode((o.quality||'').toUpperCase() === '4K' ? 2160 : 1080);
  }
  playUrl(o);
}

// ---- 转码时的档位高亮（避免"状态说 2160p、按钮还停在 1080P"的割裂）----
const TC_MARK = ' · 转码中';
function clearTcMarks(){
  document.querySelectorAll('#vquality .pl').forEach(x=>{
    if(x.textContent.endsWith(TC_MARK))
      x.textContent = x.textContent.slice(0, -TC_MARK.length);
  });
}
function markTcQuality(h){
  clearTcMarks();
  const want = h >= 2160 ? '4K' : (h >= 1080 ? '1080P' : '720P');
  let idx = cur.opts.findIndex(o => (o.quality||'').toUpperCase() === want);
  if(idx < 0) idx = cur.opts.findIndex(o => isHevc(o));   // 兜底：转码的必然是 HEVC 那档
  if(idx < 0) idx = 0;
  const btns = document.querySelectorAll('#vquality .pl');
  btns.forEach(x=>x.classList.remove('on'));
  if(btns[idx]){
    btns[idx].classList.add('on');
    btns[idx].textContent += TC_MARK;      // 一眼看出这是转码出来的
  }
  cur.cur = cur.opts[idx];
  cur.tcHeight = h;                  // 记住处于转码模式
}

function playUrl(o, useProxy, force){
  const video = $('#video');
  const hevc = isHevc(o);
  cur.cur = o; cur.proxyMode = !!useProxy;
  cur.tcHeight = null;               // 普通播放 → 退出转码模式
  const src = useProxy ? o.proxy : o.play;
  $('#now').innerHTML = `<span class="spinner"></span>第 ${cur.ep} 集 · ${esc(o.quality||'')} ${esc(o.vcodec||'')} (${o.kind}) 加载中…`;
  if(hls){ hls.destroy(); hls=null; }
  clearTcMarks();                    // 回到普通播放 → 清掉"转码中"标记
  video.removeAttribute('src'); video.load();
  const tail = () => ` · <a href="${o.direct}" target="_blank" style="color:#4ea1ff">直链</a>`
    + ` · <a href="#" onclick="playUrl(cur.cur,${useProxy?0:1},1);return false" style="color:#8b93a3">`
    + (useProxy?'切回直连':'切到代理') + `</a>`;

  // 三级降级：① 直连→代理  ② HEVC→换非 HEVC 档  ③ 提示装扩展
  let dcTimer = null;
  const clearDc = () => { if(dcTimer){ clearTimeout(dcTimer); dcTimer = null; } };
  const fail = (msg, codecIssue) => {
    clearDc();
    // 编码问题走代理也没用，直接跳到降级
    if(!useProxy && !codecIssue){
      $('#now').innerHTML = '<span class="spinner"></span>直连失败，回退到代理模式…';
      return playUrl(o, true, force);
    }
    if(hevc){
      const alt = cur.opts.findIndex(x => x !== o && !isHevc(x));
      // HLS 的 HEVC 走 MSE，浏览器普遍不支持（装扩展也无效）；MP4 的 HEVC 走原生播放器，装扩展能播
      if(o.kind === 'hls') markHlsHevcBad();      // 记下来，下次不再白等 8 秒
      if(alt >= 0){
        switchTo(alt, o.kind === 'hls'
          ? '这一集的 4K 是 HLS 封装的 HEVC，浏览器播不了'
          : 'HEVC 无法解码');
        showTranscode('', o);     // 覆盖成完整指引（转码入口 / ffmpeg 依赖提示）
        return;
      }
    }
    showTranscode(msg, o);
  };
  // ★ 真解码校验：canPlayType 会误报（Edge 说支持 HEVC 却解不出画面），
  //   所以必须等「真的解出第一帧」（readyState>=2 且 videoWidth>0）才算成功。
  //   ★ 但也别死等：分片还在正常下载（FRAG_LOADED）就再宽限 8 秒，最多 2 次 ——
  //     否则 CDN 慢一点就被误判成「浏览器无法解码」，白白降档还写进 localStorage。
  let dcExtend = 0;
  const armDecodeCheck = (extend) => {
    clearDc();
    if(extend && ++dcExtend > 2){
      const v = $('#video');
      if(v.readyState < 2 || !v.videoWidth) fail('该清晰度浏览器无法解码（一直没解出画面）');
      return;
    }
    dcTimer = setTimeout(() => {
      const v = $('#video');
      if(v.readyState < 2 || !v.videoWidth) fail('该清晰度浏览器无法解码');
    }, 8000);
  };
  const done = () => {
    clearDc();
    $('#now').innerHTML =
      `第 ${cur.ep} 集 · ${esc(o.quality||'')} ${esc(o.vcodec||'')} (${o.kind})${tail()}`;
    // ---- 续播：同一集上次看到哪就从哪继续（每个会话只做一次）----
    if(!cur.resumed){
      cur.resumed = true;
      const saved = getPos(cur.id, cur.ep), v = $('#video');
      if(saved > 15 && (!isFinite(v.duration) || saved < v.duration - 20)){
        try{ v.currentTime = saved; }catch(e){}
        $('#hint').innerHTML = `⏱ 已从 <b>${fmtTime(saved)}</b> 继续播放 · `
          + `<a href="#" onclick="clearPos(cur.id,cur.ep);`
          + `document.querySelector('#video').currentTime=0;`
          + `document.querySelector('#hint').innerHTML='';return false">从头开始</a>`;
      }
    }
  };

  // 已知不支持 HEVC（且用户没点「仍然尝试」）→ 直接换档，不浪费时间加载
  if(hevc && !HEVC_OK && !force){
    const alt = cur.opts.findIndex(x => x !== o && !isHevc(x));
    if(alt >= 0){
      switchTo(alt, '浏览器不支持 HEVC');
      showTranscode(`该清晰度是 ${esc(o.vcodec)} (HEVC)，当前浏览器不支持硬解。`, o);
      return;
    }
    return showTranscode(`该清晰度是 ${esc(o.vcodec)} (HEVC)，当前浏览器不支持硬解。`, o);
  }
  // ★ 本浏览器已知播不了「HLS 封装的 HEVC」→ 立刻提示，不再白等 8 秒解码校验
  if(hevc && o.kind === 'hls' && hlsHevcBad() && !force){
    const alt = cur.opts.findIndex(x => x !== o && !isHevc(x));
    if(alt >= 0){
      switchTo(alt, '这一集的 4K 是 HLS 封装的 HEVC（本浏览器已知不支持）');
      showTranscode('', o);
      return;
    }
    return showTranscode('这一集的 4K 是 HLS 封装的 HEVC，浏览器播不了。', o);
  }
  if(o.kind === 'hls'){
    if(window.Hls && Hls.isSupported()){
      hls = new Hls({maxBufferLength:30, enableWorker:true});
      hls.loadSource(src); hls.attachMedia(video);
      hls.on(Hls.Events.ERROR, (e,data)=>{
        if(!data.fatal) return;
        const codecIssue = ['fragParsingError','bufferAppendError',
                            'bufferAddCodecError','fragParsedError'].includes(data.details);
        fail('播放出错：' + data.details, codecIssue);
      });
      hls.on(Hls.Events.FRAG_LOADED, () => {
        // ★ 只更新进度提示，绝不能在这里判成功 —— 分片「加载完」不等于「解出画面」。
        //   之前这里直接调 done()，把解码校验清掉了，于是出现「状态显示播放中但画面全黑」。
        if(!video.videoWidth){
          $('#now').innerHTML = '<span class="spinner"></span>分片已加载，等待解码出画面…';
          armDecodeCheck(true);          // 还在正常下载 → 再宽限 8 秒
        }
      });
      video.onloadeddata = done;        // 真解出第一帧才算成功
      armDecodeCheck();
    } else if(video.canPlayType('application/vnd.apple.mpegurl')){
      video.src = src; video.onloadeddata = done; video.onerror = () => fail('播放失败');
      armDecodeCheck();
    } else {
      $('#now').textContent = '浏览器不支持 HLS';
    }
  } else {
    video.src = src;
    video.onloadeddata = done;          // 必须等第一帧真解码出来
    video.onerror = () => fail(`播放失败：${esc(o.vcodec||'')} 编码浏览器无法解码`);
    armDecodeCheck();
  }
  video.play().catch(()=>{});
}

let tcRetry = { t: 0, n: 0 };
async function doTranscode(h, silent){
  const o = cur.cur; if(!o) return;
  if(!silent && !confirm('转码会让服务器实时转出视频流（约 3~14 Mbps 持续上行带宽）。\n'
            + '这是唯一能看这种 4K 的方式（浏览器装扩展也播不了）。\n\n确认开始转码？')) return;
  const video = $('#video');
  if(!h) h = ((o.quality||'').toUpperCase() === '4K') ? 2160 : 1080;
  const start = Math.floor(video.currentTime || 0);
  $('#hint').innerHTML = `转码目标：<a href="#" onclick="doTranscode(2160);return false">4K</a>`
    + `<a href="#" onclick="doTranscode(1080);return false">1080P</a>`
    + `<a href="#" onclick="doTranscode(720);return false">720P</a>`;
  $('#now').innerHTML = `<span class="spinner"></span>启动转码 H.264 ${h}p（从 ${start}s）…`
    + `正在实测编码器并等首片，可能要 10~20 秒`;
  const d = await jget(`/api/tc?videoId=${encodeURIComponent(cur.id)}`
    + `&code=${encodeURIComponent(cur.code)}&ep=${cur.ep}&h=${h}&start=${start}`);
  if(!d.ok){ $('#now').textContent = '转码失败：' + (d.msg||''); return; }
  if(hls){ hls.destroy(); hls=null; }
  video.removeAttribute('src'); video.load();
  hls = new Hls({maxBufferLength:30, enableWorker:true});
  hls.loadSource(d.m3u8); hls.attachMedia(video);
  let errShown = false;
  hls.on(Hls.Events.ERROR, (e,data)=>{
    if(!data.fatal || data.details === 'bufferStalledError') return;
    // 会话可能已被回收 / ffmpeg 中途挂了 → 自动重开一次（不再弹确认框，最多 2 次/分钟）
    if(!errShown && /manifest|levelLoad|fragLoad|internalException/i.test(data.details||'')){
      const now = Date.now();
      if(now - tcRetry.t > 60000){ tcRetry.t = now; tcRetry.n = 0; }
      if(tcRetry.n < 2){
        tcRetry.n++; errShown = true;
        $('#now').innerHTML = '<span class="spinner"></span>转码会话失效，正在重开…';
        setTimeout(()=>doTranscode(h, true), 800);
        return;
      }
    }
    let msg = data.details;
    try{ const r = JSON.parse(data.response && data.response.text); if(r && r.msg) msg = r.msg; }catch(e){}
    $('#now').textContent = '转码播放出错：' + msg;
  });
  hls.on(Hls.Events.FRAG_LOADED, () => {
    markTcQuality(h);                  // 高亮对应的清晰度档 + 标"转码中"
    $('#now').innerHTML = `第 ${cur.ep} 集 · <b>转码播放 H.264 ${h}p</b>`
      + (d.cached ? '（缓存命中）' : ` · 编码器 ${esc(d.encoder||'')}`)
      + ` · 可拖动`;
  });
  video.play().catch(()=>{});
}

$('#kw').addEventListener('keydown', e => { if(e.key==='Enter') doSearch(); });
doSearch();
</script>
</body>
</html>
"""


FAVICON = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
           b'<rect width="64" height="64" rx="14" fill="#0f1115"/>'
           b'<circle cx="32" cy="32" r="20" fill="none" stroke="#4ea1ff" stroke-width="4"/>'
           b'<path d="M26 21 L46 32 L26 43 Z" fill="#4ea1ff"/></svg>')

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>测试·某动漫 · 需要访问令牌</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0f1115;color:#e6e8ee;font:15px/1.7 "Segoe UI","Microsoft YaHei",sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
  .box{background:#171b22;border:1px solid #232833;border-radius:14px;padding:32px 30px;
       max-width:440px;width:100%;box-shadow:0 20px 60px #0008}
  h1{font-size:19px;margin-bottom:6px;color:#4ea1ff}
  p{color:#8b93a3;font-size:13.5px;margin-bottom:18px}
  label{display:block;font-size:13px;color:#a9b2c3;margin-bottom:6px}
  input{width:100%;background:#11151c;border:1px solid #2b3240;border-radius:9px;
        padding:11px 13px;color:#e6e8ee;font-size:14px;outline:none;font-family:ui-monospace,monospace}
  input:focus{border-color:#4ea1ff}
  button{margin-top:14px;width:100%;background:#2a6fd6;border:0;color:#fff;border-radius:9px;
         padding:11px;font-size:15px;cursor:pointer}
  button:hover{background:#3a80e8}
  .err{color:#ff6b6b;font-size:13px;margin-top:10px;min-height:18px}
  .hint{margin-top:20px;padding-top:16px;border-top:1px solid #232833;color:#6b7484;font-size:12.5px;line-height:1.8}
  code{background:#11151c;border:1px solid #232833;border-radius:5px;padding:1px 6px;font-size:12px;color:#9fb6d6}
</style>
</head>
<body>
<div class="box">
  <h1>测试•某动漫</h1>
  <p>这是一个需要访问令牌的私有站点。请输入令牌继续。</p>
  <label for="t">访问令牌（token）</label>
  <input id="t" type="password" placeholder="粘贴 token 后回车" autofocus autocomplete="off">
  <button onclick="go()">进入</button>
  <div class="err" id="e"></div>
  <div class="hint">
    令牌在服务器上的 <code>webapp/.token</code> 文件里。<br>
    也可以直接访问 <code>https://你的域名/?k=令牌</code>，首次访问后会记住 30 天。
  </div>
</div>
<script>
function go(){
  const v = document.getElementById('t').value.trim();
  if(!v){ document.getElementById('e').textContent = '请输入令牌'; return; }
  location.href = '/?k=' + encodeURIComponent(v);
}
document.getElementById('t').addEventListener('keydown', e => { if(e.key==='Enter') go(); });
</script>
</body>
</html>
"""


class Server(ThreadingHTTPServer):
    """★ 默认 listen backlog 只有 5。hls.js 拉转码分片 + ffmpeg 经本机代理猛拉源分片时，
    积压连接会被系统直接拒掉（ffmpeg 报 `Connection to tcp://127.0.0.1:8000 failed`），
    表现成「转码看着在跑，突然就断了」。放到 128，并让工作线程随主进程退出。"""
    daemon_threads = True
    request_queue_size = 128
    allow_reuse_address = True


if __name__ == "__main__":
    # ★ 关掉 stdout 块缓冲：日志被重定向（比如从别的程序拉起、或写到文件）时，
    #   Python 默认攒 8KB 才吐一次，「[tc] xxx 失败」这种关键行要等很久甚至丢失。
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
    print("正在自举客户端（bootstrap → 设备池）…")
    try:
        pool = _ensure_pool()
        print(f"  设备池已建 {len(pool)} 个身份（随机生成，不使用抓包里的真实 deviceId）")
        for i, c in enumerate(pool[:3]):
            print(f"    [{i}] {c.device_id[:32]}…")
        if len(pool) > 3:
            print(f"    … 共 {len(pool)} 个")
        print(f"  masterKey(第1个) = {pool[0].mk.decode()}")
        if pool[0].negotiate_info:
            print(f"  negotiate deviceSecret 一致: "
                  f"{(pool[0].negotiate_info or {}).get('deviceSecret') == pool[0].mk.decode()}")
    except Exception as ex:
        print(f"  自举失败（页面会在首次请求时重试）: {ex}")
    print(f"  🎬 播放模式：直链优先（MP4 全直连；HLS 只代理 m3u8，分片走直链）→ 服务器几乎不耗带宽")
    print(f"  🎭 设备池大小：{DEVICE_POOL_SIZE}（MYUKO_POOL 可调）")

    if ACCESS_TOKEN:
        print(f"\n  🔒 已启用访问令牌")
        print(f"     入口： http://127.0.0.1:{PORT}/?k={ACCESS_TOKEN}")
        print(f"     公网： https://<你的隧道域名>/?k={ACCESS_TOKEN}   （首次访问后种 Cookie，之后可省略）")
    else:
        print("\n  ⚠️  未设置访问令牌（MYUKO_TOKEN），任何能访问到本端口的人都可用。")
        print("     仅本机使用没问题；要挂公网请先设置：")
        print('       set MYUKO_TOKEN=<一长串随机字符>   （PowerShell: $env:MYUKO_TOKEN="..."）')
    print(f"  代理白名单域名后缀：{', '.join(ALLOW_HOST_SUFFIX)}")
    print(f"  单 IP 限流：{RATE_LIMITS}   并发转码上限：{MAX_TRANSCODES}")

    srv = Server(("127.0.0.1", PORT), Handler)
    atexit.register(_shutdown_children)
    _start_sweeper()
    print(f"\n  本地播放站已启动 →  http://127.0.0.1:{PORT}")
    print(f"  转码缓存目录：{TC_ROOT}")
    print(f"    · 会话空闲 {TC_MAX_IDLE // 60} 分钟回收（下次开转码时顺带清）")
    print(f"    · 每 {TC_SWEEP_SEC // 60} 分钟扫一次盘，删掉重启后的残留目录")
    print(f"    · 总量上限 {TC_MAX_MB} MB，超了从最久没人看的会话开始丢"
          f"（MYUKO_TC_MAX_MB / MYUKO_TC_IDLE / MYUKO_TC_SWEEP 可调）\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown_children()
        srv.server_close()
        print("\n已停止（转码进程已结束，转码缓存已清理）")

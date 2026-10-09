# 测试•某动漫 · 本地播放站

一个纯 Python 的影片搜索 / 播放站点：自己拉取配置、自己生成设备身份、自己加解密，
**不依赖抓包、不依赖 native so**。

---

## 一、依赖

| 依赖 | 版本要求 | 是否必须 | 说明 |
|---|---|---|---|
| **Python** | **3.10+** | ✅ 必须 | 代码用了 `X \| None` 联合类型语法 |
| **pycryptodome** | 任意 | ✅ 必须 | bootstrap.jpg 的 AES-256-CBC 解密、maes |
| **ffmpeg** | 4.4+ | ⭕ 可选 | 仅「HEVC 转码兜底」用；不装则 4K/HEVC 档无法转码播放 |
| playwright | 任意 | 🔧 仅测试 | 跑 `browser_test.py` 自动化验证用，复用系统 Edge |
| hls.js | — | — | 前端从 CDN 自动加载，无需安装 |

> 除 `pycryptodome` 外**全部是 Python 标准库**（`http.server` / `urllib` / `hashlib` / `hmac` …）。

### 安装依赖

```bash
pip install pycryptodome
```

ffmpeg 可选（Windows）：

```bash
winget install Gyan.FFmpeg
```

---

## 二、运行

### 1. 设置访问令牌（强烈建议）

```powershell
# PowerShell
$env:MYUKO_TOKEN = "你自己的一长串随机字符"
python webapp_server.py
```

```cmd
:: CMD
set MYUKO_TOKEN=你自己的一长串随机字符
python webapp_server.py
```

```bash
# Git Bash
export MYUKO_TOKEN="你自己的一长串随机字符"
python webapp_server.py
```

或者直接用现成的脚本（自动读取 `.token` 文件）：

```cmd
start.bat
```

### 2. 打开

```
http://127.0.0.1:8000/?k=<你的令牌>
```

首次带 `?k=` 访问后会种 30 天 Cookie，之后直接开 `http://127.0.0.1:8000/` 即可。
没带令牌会看到一个输入框页面，粘贴令牌就能进。

---

## 三、停止

```cmd
stop.bat
```

或手动：

```powershell
# 找到占用 8000 端口的进程并结束
Get-NetTCPConnection -LocalPort 8000 -State Listen |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

```bash
# Git Bash / Linux
netstat -ano | grep ":8000.*LISTENING" | awk '{print $5}' | xargs -r taskkill //F //PID
```

前台运行时直接 `Ctrl + C` 也可以。

---

## 四、环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `MYUKO_TOKEN` | 空（不鉴权） | 访问令牌。**挂公网前务必设置** |
| `MYUKO_POOL` | `8` | 设备池大小。启动时随机生成 N 个 deviceId，访客按 Cookie 稳定分配其中一个；某个被封只影响 1/N |
| `MYUKO_ALLOW_HOSTS` | 见代码 | 代理白名单域名后缀（逗号分隔），防 SSRF。**`/api/play` 给出的域名会自动加进来**，一般不用手动加 |
| `MYUKO_TC_IDLE` | `1800` | 转码会话空闲多少秒回收 |
| `MYUKO_TC_SWEEP` | `600` | 后台清扫转码缓存的间隔（秒） |
| `MYUKO_TC_MAX_MB` | `8000` | 转码缓存总量上限（MB），超了从最旧会话开始丢；`0` = 不限 |
| `MYUKO_TC_TIMEOUT` | `40` | 等「首片产出」的超时（秒），超时即判定该编码器不可用并换下一个 |

---

## 五、目录结构

```
webapp/
├── webapp_server.py      ← ★ 入口：HTTP 服务 + 单页前端（含播放器）
├── myuko_pure.py         ← 协议客户端（自举 + 搜索 + 播放解析）
├── magic_v3.py           ← v3 加密帧 编解码
├── signing.py            ← 请求头签名（x-signature / x-fp-sign …）
├── bootstrap_keys.py     ← bootstrap.jpg 隐写配置解密
├── ecsm.py               ← 六算法链（XOR/RC4/Base64/TEA/ChaCha20/Blowfish）
├── maes.py               ← maes 块加密
├── deviceid.py           ← deviceId 派生
├── start.bat / stop.bat  ← 启停脚本
├── browser_test.py       ← 自动化验证（需 playwright）
├── shots/                ← 验证截图（横幅 / 播放 / 隧道）
├── .token                ← 访问令牌（勿提交）
└── bootstrap*.jpg/json   ← 自检样本
```

---

## 六、接口

| 路由 | 说明 |
|---|---|
| `GET /` | 前端页面（搜索 / 详情 / 剧集 / 播放器） |
| `GET /api/search?keyword=&page=&size=` | 搜索 |
| `GET /api/detail?videoId=` | 详情（含线路列表） |
| `GET /api/episodes?videoId=&code=` | 剧集列表 |
| `GET /api/play?videoId=&code=&ep=` | 解析播放地址（返回 `direct` 直链 + `play` 播放用地址） |
| `GET /api/seg?u=` / `/api/seg/<name>.ts?u=` | 代理转发（m3u8 重写 / 分片 / 密钥） |
| `GET /api/img?u=` | 封面代理 |
| `GET /api/tc?u=&start=&h=` | 启动 ffmpeg 转码会话（HEVC → H.264） |
| `GET /api/tc/playlist.m3u8?sid=` / `/api/tc/seg?sid=&f=` | 转码后的播放列表 / 分片 |
| `GET /api/health` | 自检 |

**播放策略**：MP4 走 CDN 直链（服务器零带宽）；HLS 只代理 m3u8（约 30 KB），分片直连；
只有 `#EXT-X-KEY` 密钥和「浏览器不支持 HEVC」时的转码才真正吃服务器带宽。

**播放进度记忆**：每 5 秒把进度存进 `localStorage`（key = `myuko_pos_<videoId>_<ep>`），
再次打开该集自动续播，并提示「⏱ 已从 0:19 继续播放 · 从头开始」。
只在 `15s < 进度 < 时长-20s` 时记录，避免存成片头或片尾。

**端点容灾（DoH 兜底）**：API 域名一旦系统 DNS 解析失败，整站会全挂。
`myuko_pure.open_url()` 会先走系统 DNS，失败则用 **DoH**（AliDNS / DoH.pub）
解析出 IP 并直连（SNI 仍用域名）。正常情况下零开销，只在失败时触发。

**选台与降级策略**（重要）：
1. 默认自动选**非 HEVC** 的档（H.264 任何浏览器都能播）
2. **不做自动转码** —— 转码会持续占用服务器上行带宽，默认一律走 CDN 直链
3. **真解码校验**：`canPlayType` 会误报（Edge 声称支持 HEVC 却解不出画面），
   所以必须等「真的解出第一帧」（`readyState>=2` 且 `videoWidth>0`）才算成功，
   8 秒内没解出就判定为不支持
4. 判定不支持后：优先自动切到非 HEVC 档；没有其他档 → **提示安装 HEVC 扩展**
   （带免费版/官方版商店链接 + 直链下载）
5. 首页顶部有**常驻提示横幅**，说明 4K 是 H.265 编码、各平台如何获得解码支持（可「不再提示」）
6. 服务器转码保留为**手动入口**（在提示里以灰色小字给出，点了会弹确认框警告消耗带宽）

### 关于 4K / HEVC

4K 档是 **H.265 / HEVC** 编码。能不能播**取决于两个因素**，其中第二个常被忽略：

**① 系统有没有 HEVC 解码器**

| 平台 | 情况 |
|---|---|
| Windows | 需装 **HEVC 视频扩展**：[免费版](https://apps.microsoft.com/detail/9n4wgh0z6vhq) / [官方版 ¥7](https://apps.microsoft.com/detail/9nmzlz57r3t7) |
| macOS / iOS | 原生支持，无需安装 |
| 多数 Android | 原生支持 |
| Linux | 取决于发行版与 GPU 驱动 |

**② 封装格式（关键！这决定了扩展有没有用）**

| 封装 | 播放路径 | HEVC 能否播 |
|---|---|---|
| **MP4** | `<video src>` 走浏览器**原生播放器** | ✅ 装了扩展就能播（Windows 上用系统解码器） |
| **HLS** | hls.js 转封装后喂 **MSE** | ❌ **装扩展也没用** —— 浏览器 MSE 对 HEVC 的支持是「谎报」的（`MediaSource.isTypeSupported('video/mp4; codecs="hvc1..."')` 返回 `true`，但实际解不出画面，`videoWidth` 恒为 0） |

实测（凡人修仙传）：第178集 4K 是 **MP4** → 直接 3840×2160 播放 ✅；
第1集 4K 是 **HLS** → 卡住（`readyState=4` 但 `videoWidth=0`，即"在播放但全黑"），
前端会在 8 秒后判定失败并自动切回 **1080P H264**。

**所以：同一部剧不同集可能一个能播 4K 一个不能，这不是扩展装没装的问题，是源的封装格式不同。**

**前端策略**：
1. 默认自动选**非 HEVC** 档（H.264 任何浏览器都能播）
2. **不做自动转码**（会占服务器上行带宽）
3. **真解码校验**取代 `canPlayType`：`readyState >= 2 && videoWidth > 0` 才算成功，
   8 秒不满足判为不支持（注意：`FRAG_LOADED` 只代表分片下载完，**不代表解出画面**）
   —— 实测本地化 hls.js 后它会自己快速报致命错误，**通常 0.5 秒就回退**，不用等满 8 秒
4. 不支持 → 优先自动切非 HEVC 档，然后按**封装格式**给不同指引：

   | 情况 | 提示 |
   |---|---|
   | **HLS 封装**的 HEVC | 提「浏览器无法直接播，需服务器转码」+ `▶ 转码播放 4K/1080P`<br>（**不再提浏览器扩展** —— 那种情况装了确实没用）|
   | HLS 封装 + **服务器没装 ffmpeg** | 提示装依赖：`winget install Gyan.FFmpeg` + 下载页 |
   | **MP4 封装**的 HEVC | 提示装浏览器扩展（这种情况装了**确实能解决**）|

5. 会记住「本浏览器播不了 HLS-HEVC」（localStorage），之后不再重复试探
6. 首页常驻提示横幅（可「不再提示」）
7. 转码保留为**手动入口**（点 `▶ 转码播放` 会弹确认框警告消耗带宽）

> 前端通过 `/api/health` 拿到 `ffmpeg` / `encoder` 状态，用来决定提示哪种依赖。

### 行为矩阵

| 内容 | 封装 | 条件 | 结果 |
|---|---|---|---|
| 1080P H264 | HLS | 全部 | ✅ 直连播放（默认选它） |
| 4K HEVC | MP4 | 装了扩展 | ✅ 原生 4K 播放 |
| 4K HEVC | MP4 | 没装扩展 | ⚠️ 提示装扩展（装了能播） |
| 4K HEVC | HLS | 服务器有 ffmpeg | ⚠️ 提示 + `▶ 转码播放 4K` 按钮 |
| 4K HEVC | HLS | 服务器无 ffmpeg | ⚠️ 提示装 ffmpeg（给命令） |

---

### 转码（可选，默认不触发）

点提示里的「▶ 转码播放 4K / 1080P」会弹确认框，确认后：

`/api/tc?videoId=&code=&ep=&h=2160` 会启动 ffmpeg 实时转 H.264 HLS：

- **编码器自动选型**：`h264_nvenc` → `h264_amf` → `h264_qsv` → `libx264`，
  且每个都会**按目标分辨率 + 目标码率实跑验证**（ffmpeg 会「列出」nvenc 但 AMD 机器上跑不了；
  小分辨率探针通过也不代表 4K 能过）
- **运行期自动降级**：首片没出来就换下一个编码器重试，并把失败原因回传到前端
  （以前只会看到一个裸 404）
- **按集缓存**：key = `videoId|code|ep|高度`，重看不重转；拖动进度超过 8 秒会重开会话
- **码率**：2160→14M / 1440→9M / 1080→6M / 720→3M / 480→1.5M
- **音频直接 copy**，不重编
- 实测速度：4K→4K `libx264 veryfast` 1.69x、`h264_amf` 3.06x 实时
- 并发上限 2 个会话；`/api/tc` 限流 6 次/分（**按 IP+路径**分桶）

#### 转码踩过的坑（都是「看着莫名，其实很具体」）

| 现象 | 真因 | 现在的做法 |
|---|---|---|
| 4K 转码瞬间失败，`encoder->Init() failed with error 5` | `scale=-2:2160` 对**宽幅源**会按比例把宽度算爆：实测源 `3840x1598`（2.40:1）→ 输出 `5190x2160`，**超过 AMD 编码器 4096 的最大宽度**。换成 16:9 的 `3840x2160` 源就没事，所以同一台机器有的剧能转有的不能 | `scale=-2:'min(2160,ih)'` —— 只缩不放，宽度自然合规 |
| 同上（另一种触发） | 10bit 源（HEVC Main10）解出来是 `p010`，AMD 驱动 <23.30 直接拒绝 | 滤镜链尾部补 `format=yuv420p` |
| 转码跑一会儿就断，日志里 `Connection to tcp://127.0.0.1:8000 failed` | hls.js 拉转码分片 + ffmpeg 经本机代理拉源分片，默认 listen backlog 只有 5，积压连接被系统拒掉 | `request_queue_size = 128` |
| 控制台看不见关键日志 | stdout 被重定向时 Python 默认块缓冲，攒 8KB 才吐 | 启动时 `sys.stdout.reconfigure(line_buffering=True)` |
| 播放列表一直 404 | 会话已死（ffmpeg 退出）但映射还留着 | 死会话立刻回收 + 返回真实原因，前端自动重开一次 |
| 分片全部 `403`（看着像 CDN 挂了） | 分片 CDN 与 m3u8 **不同域**，而且域名只在**播放列表正文**里出现（实测 m3u8 在 `img.nxjunyu.asia`，分片在 `p4-plat.wskwai.com`） | `learn_m3u8_hosts()`：解析播放列表时把分片/密钥域名一并记入白名单 |
| `detected format mpegts extension none mismatches allowed extensions in url …pdf` | CDN 分片是 `.png` / `.pdf` 伪装的 MPEG-TS，而 ffmpeg 的 HLS demuxer 默认按「整串 URL 最后一个点」判扩展名（`-allowed_extensions ALL` 也救不了） | 加 `-extension_picky 0`，让它按内容嗅探 |

#### 转码缓存怎么清（`%TEMP%\myuko_tc`）

4K 转一集能到 **1.2 GB**，所以「什么时候会被清」很重要。四道闸门：

| 时机 | 行为 |
|---|---|
| 会话空闲 **30 分钟** | 下次开转码时顺带回收（`MYUKO_TC_IDLE`，秒） |
| 每 **10 分钟** | 后台线程扫盘：删掉「不属于本进程会话」的目录 —— 也就是上次运行的残留（`MYUKO_TC_SWEEP`，秒） |
| 总量超 **8 GB** | 从「最久没人看」的会话开始丢（`MYUKO_TC_MAX_MB`，0=不限） |
| 进程退出 / `stop.bat` | 杀掉所有 ffmpeg 子进程 + 清空缓存目录 |

> 为什么要单独「扫盘」：会话是靠**内存里**的 `SESSIONS` / `TC_BY_KEY` 索引的，
> 服务一重启，磁盘上那些目录就再也不可能被命中 —— 光靠内存超时清理**永远删不到它们**
> （实测残留过 **13 个目录 / 12.34 GB**）。
>
> `stop.bat` 用 `taskkill /F /T`（连子进程）：不然 Ctrl+C / 停止脚本只结束 python，
> ffmpeg 会变孤儿继续跑完整集、继续往缓存目录写 —— 「停止」之后磁盘还在涨。

**转码时的 UI**：开始转码后，对应的清晰度档会自动高亮并标注 **` · 转码中`**
（如 `4K H265 · 转码中`），避免"状态栏说 2160p、按钮还停在 1080P"的割裂。
此时点 HEVC 档的 chip 会按该档高度重开转码；点非 HEVC 档则退出转码模式回到普通直连播放。

---

## 七、自动化验证

`browser_test.py` 会用真实浏览器（复用系统 Edge）跑一遍
「打开 → 搜索 → 详情 → 选集 → 播放」，并检查 `<video>` 的真实状态、截图。

```bash
pip install playwright
python browser_test.py
```

输出示例：

```
② 搜索「凡人修仙传」   结果 2 条，首条 = 凡人修仙传 年番
③ 打开详情 + 选集      凡人修仙传 年番  剧集 192 个
④ 点第01集（自动选台）
   自动选中档位 : 1080P H264
   分辨率       : 1920x1080
   readyState   : 4   已缓冲 39.89s
   播放进度     : 9.36s / 1203.2s   paused=False      ← 确实在播
   截图 → shots_browser_ep1.png
```

> 需要 `channel="msedge"` 复用系统 Edge（不下载 Playwright 自带浏览器）。
> 没有 Edge 的话把 `browser_test.py` 里的 `channel="msedge"` 去掉即可。

---

## 八、常见问题

**Q：打不开 / 显示「未授权」**
A：URL 后面加 `?k=<令牌>`。令牌在 `webapp/.token`。

**Q：4K 播不了，提示 HEVC**
A：4K 档是 H.265 编码，浏览器需要系统级 HEVC 解码支持。
点提示里的「转码播放（H.264）」用 ffmpeg 实时转（需装 ffmpeg），或改选 1080P H264 档。
现在会自动优先选浏览器能播的档，一般不会碰到。

**Q：某集一直转圈 / 提示「转码失败：…」**
A：现在会把 ffmpeg 的真实原因回显在播放器下方（例如编码器不支持该分辨率），照着改或换 1080P 档即可。
转码会话失效时前端会自动重开一次。排查用日志：`%TEMP%\myuko_tc\<sid>\ffmpeg.log`。

**Q：运行 start.bat 时报「'xxxx' 不是内部或外部命令」**
A：`start.bat` / `stop.bat` **必须保持 CRLF 换行**。实测 LF 换行会让 cmd 解析错位，
把 `rem` / `echo` 行的开头吃掉，中文还会变乱码。重新保存时别让编辑器改成 LF。

**Q：提示「目标域名不在白名单内」（403）**
A：CDN 域名会轮换（实测同一集昨天在 `nxjunyu.asia`、今天变 `v4-kling.kechuangai.com`），
写死的白名单必然漏。现在 **`/api/play` 解析出来的域名会自动进白名单**（客户端塞进来的
`u=` 仍然只认静态白名单，内网 / 回环 / IP 直连仍然一律拒绝）。
如果还遇到新域名，用 `MYUKO_ALLOW_HOSTS=xxx.com` 追加。

**Q：转码缓存占了多少、会不会自己清掉**
A：见上文「转码缓存怎么清」。想立刻清空：跑 `stop.bat`，或手动删 `%TEMP%\myuko_tc`。

**Q：端口 8000 被占用**
A：改 `webapp_server.py` 顶部的 `PORT`，或先跑 `stop.bat`。

**Q：挂公网安全吗？**
A：本机只监听 `127.0.0.1`（隧道是出站连接，不用开入站端口）。已内置：
访问令牌、SSRF 域名白名单（禁止内网/IP 直连）、按 IP 限流、转码并发上限。
**再叠加 Cloudflare Access（Zero Trust）做一层登录** 才够稳妥。

---

## 九、注意事项

- 所有请求都走**随机生成的设备身份**（设备池），不使用任何真实设备信息。
- 服务端有风控与设备注册，请**低频使用**。
- 4K 单集可达 1.25 GB，注意流量。
- 仅供个人学习研究，请遵守相关服务条款与当地法律法规。

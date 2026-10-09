"""deviceId / masterKey 派生（还原自 dex B5.b/B5.n/B5.t、Ud.AbstractC1317g.q）。

deviceId 是一个**多行 material 字符串**（不是哈希），每行 `key:{len(value_bytes)}:{value}`：
    ruleVersion:{len}:{rv}
    sourceType:{len}:{type}          # oaid | uuid | uuid_timestamp
    sourceValueHash:{len}:{hex(sha256(源值))}
    hardwareFingerprint:{len}:{BuildJSON}
其中 BuildJSON = "\n".join(同理格式化的 board/brand/device/hardware/manufacturer/model/product)
uuid_timestamp 的源值 = 无连字符小写 uuid 与毫秒时间戳字符串逐位交错（B5.t.j）。

masterKey = hex( HMAC-SHA256( utf8(masterSecret), utf8("device:" + deviceId) ) )   # 64 个 ASCII hex 字符
negotiate 请求体 = {"deviceId": deviceId}（设备绑定密钥加密）；响应先用设备密钥解、失败回落 raw masterSecret。
"""
import hashlib, hmac, uuid, time, json


def _kv(key: str, val: str) -> str:
    n = len(val.encode("utf-8"))
    return f"{key}:{n}:{val}"


def build_json(board="", brand="", device="", hardware="", manufacturer="", model="", product="") -> str:
    return "\n".join([_kv("board", board), _kv("brand", brand), _kv("device", device),
                      _kv("hardware", hardware), _kv("manufacturer", manufacturer),
                      _kv("model", model), _kv("product", product)])


def uuid_timestamp_source(now_ms: int | None = None, u: str | None = None) -> str:
    """B5.t.j：uuid 去连字符，时间戳数字逐位插入。"""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    u = (u or str(uuid.uuid4())).lower().replace("-", "")
    ts = str(now_ms)
    out, i = [], 0
    for ch in u:
        if i < len(ts):
            out.append(ts[i]); i += 1
        out.append(ch)
    if i < len(ts):
        out.append(ts[i:])
    return "".join(out)


def device_id(rule_version=1, source_type="uuid_timestamp", source_value=None, build_json_str=None) -> str:
    vh = hashlib.sha256(source_value.encode()).hexdigest()
    material = "\n".join([
        _kv("ruleVersion", str(rule_version)),
        _kv("sourceType", source_type),
        _kv("sourceValueHash", vh),
        _kv("hardwareFingerprint", build_json_str if build_json_str is not None else build_json()),
    ])
    return material


def master_key(master_secret: str, device_id_str: str) -> bytes:
    """device_id_str 传 material 串；内部先 sha256 成 64hex（=x-device-id 头值）再 HMAC。
    （signing 子代理经 B5.t.g→t.k 代码确认的修正）"""
    did_hex = x_device_id_header(device_id_str)
    return hmac.new(master_secret.encode(), ("device:" + did_hex).encode(), hashlib.sha256).hexdigest().encode()


def x_device_id_header(device_id_str: str) -> str:
    """x-device-id 头 = hex(SHA-256(deviceId material))（B5.t.g→t.k 代码确认）。"""
    return hashlib.sha256(device_id_str.encode()).hexdigest()


if __name__ == "__main__":
    did = device_id(source_value=uuid_timestamp_source())
    print(json.dumps({"deviceId": did}, indent=2))
    print("x-device-id =", x_device_id_header(did))

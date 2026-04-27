"""
Pikmin Bloom Proxy Sniffer
---------------------------
原理：在電腦上開 mitmproxy，讓模擬器透過它上網。
遊戲每次載入地圖都會向 Niantic 伺服器查詢附近菇的資料，
proxy 攔截回應、解析，直接得到座標 + 類型，完全不需要截圖或 OCR。

優點：
  - 不需要 GPS 一點一點移動
  - 無截圖/OCR 延遲，幾乎即時
  - 可在遊戲正常遊玩時背景收集

缺點/注意事項：
  - 需要 SSL Pinning Bypass（Pikmin Bloom 有憑證釘選）
  - 步驟比 scanner.py 複雜
  - 可能違反 Niantic ToS，請自行評估風險

============================================================
快速設定步驟（Mac + Android Studio AVD）：

1. 安裝 mitmproxy
   pip install mitmproxy blackboxprotobuf

2. 啟動 AVD（啟用 writable system，用來安裝系統憑證）
   emulator -avd <AVD名稱> -writable-system

3. 安裝 mitmproxy 系統憑證（只需一次）
   # 取得憑證 hash
   openssl x509 -inform PEM -subject_hash_old \\
     -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1
   # 複製憑證
   adb root && adb remount
   adb push ~/.mitmproxy/mitmproxy-ca-cert.pem \\
     /system/etc/security/cacerts/<hash>.0
   adb shell chmod 644 /system/etc/security/cacerts/<hash>.0
   adb reboot

4. 設定模擬器 Wi-Fi Proxy
   在 AVD 的 Wi-Fi 設定手動填入：
     主機：10.0.2.2（AVD 內連到宿主機的固定 IP）
     Port：8888

5. 啟動 proxy
   mitmdump -s proxy_sniffer.py --listen-port 8888

   或帶參數：
   mitmdump -s proxy_sniffer.py --listen-port 8888 \\
     --set target_sizes=Large,Giant \\
     --set target_types=Fire,Electric,Water,Crystal,Poisonous \\
     --set log_path=pikmin_found.log \\
     --set dump_unknown=true

6. 開遊戲，在地圖上移動，log 自動寫入 pikmin_found.log
============================================================

安裝：
  pip install mitmproxy blackboxprotobuf
"""

import json
import re
import math
import struct
from datetime import datetime
from mitmproxy import http
from mitmproxy import ctx

# ---------------------------------------------------------------------------
# 目標設定（可透過 --set 覆蓋）
# ---------------------------------------------------------------------------

TARGET_SIZES = ["Large", "Giant"]
TARGET_TYPES = ["Fire", "Electric", "Water", "Crystal", "Poisonous"]
LOG_PATH = "pikmin_found.log"

# 去重複：相同 size+type 且距離 < 這個值（公尺）視為同一個菇
DEDUP_RADIUS_M = 80

SIZES = ["Small", "Normal", "Large", "Giant"]
ALL_MUSHROOM_TYPES = [
    "Fire", "Crystal", "Electric", "Water", "Poisonous",
    "Red", "Yellow", "Blue", "Purple", "White", "Pink", "Gray",
    "Lavish", "Giant",
]

# Niantic 相關 hostname
NIANTIC_HOSTS = [
    "nianticlabs.com",
    "niantic.net",
    "pikmin-bloom.com",
    "pikminbloom",
    "ichigo",
]

# ---------------------------------------------------------------------------
# mitmproxy options
# ---------------------------------------------------------------------------

def load_script(loader):
    loader.add_option(
        name="target_sizes", typespec=str,
        default="Large,Giant",
        help="逗號分隔的目標大小，例如 Large,Giant",
    )
    loader.add_option(
        name="target_types", typespec=str,
        default="Fire,Electric,Water,Crystal,Poisonous",
        help="逗號分隔的目標類型",
    )
    loader.add_option(
        name="log_path", typespec=str,
        default="pikmin_found.log",
        help="找到目標時寫入的 log 檔路徑",
    )
    loader.add_option(
        name="dump_unknown", typespec=bool,
        default=False,
        help="將未解析的 Niantic 回應存成 .bin 供分析",
    )


def configure(updated):
    global TARGET_SIZES, TARGET_TYPES, LOG_PATH
    if "target_sizes" in updated:
        TARGET_SIZES = [s.strip() for s in ctx.options.target_sizes.split(",") if s.strip()]
    if "target_types" in updated:
        TARGET_TYPES = [t.strip() for t in ctx.options.target_types.split(",") if t.strip()]
    if "log_path" in updated:
        LOG_PATH = ctx.options.log_path

# ---------------------------------------------------------------------------
# 核心 addon
# ---------------------------------------------------------------------------

def _dist_m(lat1, lon1, lat2, lon2):
    dlat = (lat2 - lat1) * 111320
    dlon = (lon2 - lon1) * 111320 * math.cos(math.radians(lat1))
    return math.sqrt(dlat ** 2 + dlon ** 2)


def _read_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


def _proto_fields(data: bytes):
    """極簡 protobuf 掃描，回傳 list of (field_num, wire_type, value_or_bytes)。"""
    fields = []
    pos = 0
    while pos < len(data):
        try:
            tag, pos = _read_varint(data, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 0x7
        if field_num == 0 or field_num > 50000:
            break
        try:
            if wire_type == 0:
                val, pos = _read_varint(data, pos)
                fields.append((field_num, 0, val))
            elif wire_type == 2:
                length, pos = _read_varint(data, pos)
                if pos + length > len(data) or length > 20_000_000:
                    break
                fields.append((field_num, 2, data[pos:pos+length]))
                pos += length
            elif wire_type == 1:
                fields.append((field_num, 1, data[pos:pos+8]))
                pos += 8
            elif wire_type == 5:
                fields.append((field_num, 5, data[pos:pos+4]))
                pos += 4
            else:
                break
        except Exception:
            break
    return fields


class MushroomSniffer:

    def __init__(self):
        # (size, type) -> list of (lat, lon) already logged
        self._seen: dict[tuple, list] = {}
        self._bbproto = None  # blackboxprotobuf module（lazy import）

    def _bbp(self):
        if self._bbproto is None:
            try:
                import blackboxprotobuf
                self._bbproto = blackboxprotobuf
            except ImportError:
                self._bbproto = False
        return self._bbproto if self._bbproto else None

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not self._is_niantic(host):
            return

        body = flow.response.get_content()
        if not body:
            return

        url = flow.request.pretty_url
        method = flow.request.method
        ctx.log.debug(f"[Sniffer] {method} {url}  ({len(body)} bytes)")

        mushrooms = []
        is_rpc2 = "rpc2" in url or "rpc" in url.lower()

        # --- 嘗試 JSON 解析 ---
        try:
            data = json.loads(body)
            mushrooms = self._extract_from_json(data)
            if mushrooms:
                ctx.log.info(f"[JSON] 從 {url} 找到 {len(mushrooms)} 個候選")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # --- rpc2 / protobuf 解析 ---
        if not mushrooms and is_rpc2:
            mushrooms = self._extract_from_proto(body, url)
            if mushrooms:
                ctx.log.info(f"[Proto] 從 rpc2 找到 {len(mushrooms)} 個候選")

        # --- 文字 regex（含 protobuf 裡的 UTF-8 字串）---
        if not mushrooms:
            try:
                text = body.decode("utf-8", errors="replace")
                mushrooms = self._extract_from_text(text, url)
                if mushrooms:
                    ctx.log.info(f"[Text] 從 {url} 找到 {len(mushrooms)} 個候選")
            except Exception:
                pass

        # --- dump rpc2 回應供離線分析 ---
        do_dump = getattr(ctx.options, "dump_unknown", False)
        if do_dump or is_rpc2:
            import os, time
            dump_dir = "niantic_dumps"
            os.makedirs(dump_dir, exist_ok=True)
            safe_host = host.replace(".", "_")
            tag = "rpc2" if is_rpc2 else "other"
            fname = f"{dump_dir}/{int(time.time()*1000)}_{safe_host}_{tag}_{len(body)}.bin"
            with open(fname, "wb") as f:
                f.write(body)
            ctx.log.info(f"[Dump] {fname}")

        for m in mushrooms:
            self._log_match(m, url)

    # -----------------------------------------------------------------------

    def _is_niantic(self, host: str) -> bool:
        return any(h in host for h in NIANTIC_HOSTS)

    # -----------------------------------------------------------------------
    # JSON 遞迴萃取
    # -----------------------------------------------------------------------

    def _extract_from_json(self, data, _depth=0):
        if _depth > 20:
            return []
        results = []
        if isinstance(data, dict):
            name = (data.get("name") or data.get("displayName") or
                    data.get("title") or data.get("label") or "")
            lat  = data.get("latitude") or data.get("lat") or data.get("y")
            lon  = data.get("longitude") or data.get("lng") or data.get("lon") or data.get("x")

            if name and lat is not None and lon is not None:
                size, mtype = self._parse_name(str(name))
                if size and mtype and self._is_target(size, mtype):
                    results.append({"size": size, "type": mtype,
                                    "lat": float(lat), "lon": float(lon),
                                    "raw": str(name)})

            for v in data.values():
                results.extend(self._extract_from_json(v, _depth + 1))

        elif isinstance(data, list):
            for item in data:
                results.extend(self._extract_from_json(item, _depth + 1))

        return results

    # -----------------------------------------------------------------------
    # Protobuf 萃取（blackboxprotobuf + 手動掃描）
    # -----------------------------------------------------------------------

    def _extract_from_proto(self, data: bytes, url: str):
        results = []

        # 方法 1：blackboxprotobuf 深度遞迴搜尋
        bbp = self._bbp()
        if bbp:
            try:
                msg, _ = bbp.decode_message(data)
                results = self._search_proto_dict(msg)
                if results:
                    return results
            except Exception:
                pass

        # 方法 2：手動掃描所有 bytes 欄位，遞迴嘗試解析子 protobuf
        results = self._scan_proto_recursive(data, depth=0)
        return results

    def _search_proto_dict(self, obj, _depth=0):
        """在 blackboxprotobuf 解碼的 dict/list 裡遞迴搜尋菇的資料。"""
        if _depth > 30:
            return []
        results = []

        if isinstance(obj, dict):
            str_vals = {k: v for k, v in obj.items() if isinstance(v, str)}
            num_vals = {k: v for k, v in obj.items()
                        if isinstance(v, (int, float)) and not isinstance(v, bool)}

            name = None
            for k in str_vals:
                size, mtype = self._parse_name(str_vals[k])
                if size and mtype:
                    name = str_vals[k]
                    break

            lat = lon = None
            for k, v in num_vals.items():
                if isinstance(v, float):
                    if -90 <= v <= 90 and lat is None:
                        lat = v
                    elif -180 <= v <= 180 and lon is None:
                        lon = v
                elif isinstance(v, int):
                    fv = v / 1e7
                    if -90 <= fv <= 90 and lat is None:
                        lat = fv
                    elif -180 <= fv <= 180 and lon is None:
                        lon = fv

            if name:
                size, mtype = self._parse_name(name)
                if size and mtype and self._is_target(size, mtype):
                    results.append({"size": size, "type": mtype,
                                    "lat": lat, "lon": lon,
                                    "raw": name})

            for v in obj.values():
                results.extend(self._search_proto_dict(v, _depth + 1))

        elif isinstance(obj, list):
            for item in obj:
                results.extend(self._search_proto_dict(item, _depth + 1))

        return results

    def _scan_proto_recursive(self, data: bytes, depth=0):
        """手動掃描 protobuf，對每個 bytes 欄位遞迴嘗試解析。"""
        if depth > 8 or len(data) < 2:
            return []
        results = []

        fields = _proto_fields(data)
        if not fields:
            return []

        strings = []
        floats = []
        for fnum, wtype, val in fields:
            if wtype == 2 and isinstance(val, bytes):
                try:
                    s = val.decode("utf-8")
                    if s.isprintable():
                        strings.append((fnum, s))
                except Exception:
                    pass
                sub = self._scan_proto_recursive(val, depth + 1)
                results.extend(sub)
                for i in range(0, len(val) - 7, 8):
                    v = struct.unpack_from("<d", val, i)[0]
                    if -90 <= v <= 90 and abs(v) > 0.01:
                        floats.append(("lat_d", i, v))
                    elif -180 <= v <= 180 and abs(v) > 0.01:
                        floats.append(("lon_d", i, v))
            elif wtype in (1, 5):
                if wtype == 1 and isinstance(val, bytes) and len(val) == 8:
                    v = struct.unpack_from("<d", val)[0]
                    if -90 <= v <= 90:
                        floats.append(("lat_d", fnum, v))
                    elif -180 <= v <= 180:
                        floats.append(("lon_d", fnum, v))
                elif wtype == 5 and isinstance(val, bytes) and len(val) == 4:
                    v = struct.unpack_from("<f", val)[0]
                    if -90 <= v <= 90:
                        floats.append(("lat_f", fnum, v))
                    elif -180 <= v <= 180:
                        floats.append(("lon_f", fnum, v))

        for fnum, s in strings:
            size, mtype = self._parse_name(s)
            if size and mtype and self._is_target(size, mtype):
                lat = lon = None
                for kind, _, v in floats:
                    if "lat" in kind and lat is None:
                        lat = v
                    elif "lon" in kind and lon is None:
                        lon = v
                results.append({"size": size, "type": mtype,
                                "lat": lat, "lon": lon,
                                "raw": s})
        return results

    # -----------------------------------------------------------------------
    # Text regex 萃取
    # -----------------------------------------------------------------------

    def _extract_from_text(self, text: str, url: str):
        results = []
        for size in SIZES:
            for mtype in ALL_MUSHROOM_TYPES:
                pattern = rf"\b{re.escape(size)}\s+{re.escape(mtype)}\s+Mushroom\b"
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    if not self._is_target(size, mtype):
                        continue
                    window = text[max(0, m.start()-300): m.end()+300]
                    coords = re.findall(r"-?\d{1,3}\.\d{4,10}", window)
                    lat = lon = None
                    for c in coords:
                        val = float(c)
                        if -90 <= val <= 90 and lat is None:
                            lat = val
                        elif -180 <= val <= 180 and lon is None:
                            lon = val
                        if lat and lon:
                            break
                    results.append({"size": size, "type": mtype,
                                    "lat": lat, "lon": lon,
                                    "raw": m.group()})
        return results

    # -----------------------------------------------------------------------

    def _parse_name(self, name: str):
        upper = name.upper()
        size  = next((s for s in SIZES          if s.upper() in upper), None)
        mtype = next((t for t in ALL_MUSHROOM_TYPES if t.upper() in upper), None)
        return size, mtype

    def _is_target(self, size: str, mtype: str) -> bool:
        size_ok  = (size  in TARGET_SIZES) if TARGET_SIZES else True
        type_ok  = (mtype in TARGET_TYPES) if TARGET_TYPES else True
        return size_ok and type_ok

    def _is_duplicate(self, m: dict) -> bool:
        if m.get("lat") is None:
            return False
        key = (m["size"], m["type"])
        for lat, lon in self._seen.get(key, []):
            if _dist_m(lat, lon, m["lat"], m["lon"]) < DEDUP_RADIUS_M:
                return True
        return False

    def _log_match(self, m: dict, url: str):
        if self._is_duplicate(m):
            return
        if m.get("lat") is not None:
            key = (m["size"], m["type"])
            self._seen.setdefault(key, []).append((m["lat"], m["lon"]))

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        coord_str = (f"({m['lat']:.6f}, {m['lon']:.6f})"
                     if m.get("lat") is not None else "(座標未知)")
        entry = f"{ts}  [{m['size']} {m['type']}]  {coord_str}  raw={m['raw']!r}"
        ctx.log.warning(f"*** FOUND: {entry}")
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(entry + "\n")


addons = [MushroomSniffer()]

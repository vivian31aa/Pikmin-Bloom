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
快速設定步驟（Windows 11 + LDPlayer 9）：

1. 安裝 mitmproxy
   pip install mitmproxy

2. 啟動 proxy（本機 8888 port）
   mitmdump -s proxy_sniffer.py --listen-port 8888

   或帶參數：
   mitmdump -s proxy_sniffer.py --listen-port 8888 \\
     --set target_sizes=Large,Giant \\
     --set target_types=Fire,Electric,Water,Crystal,Poisonous \\
     --set log_path=pikmin_found.log

3. LDPlayer 設定 Proxy
   LDPlayer 設定 > 其他設定 > 網路橋接（NAT 改為橋接）
   或在 Android Wi-Fi 設定裡手動填 Proxy：
     主機：你電腦的區域 IP（ipconfig 查）
     Port：8888

4. 安裝 mitmproxy 憑證（只需一次）
   模擬器開瀏覽器前往 http://mitm.it
   下載並安裝 Android 憑證

5. SSL Pinning Bypass（關鍵步驟）
   方法 A — Frida（推薦）：
     pip install frida-tools
     adb push frida-server /data/local/tmp/
     adb shell "chmod 755 /data/local/tmp/frida-server"
     adb shell "/data/local/tmp/frida-server &"
     frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -U -f jp.pokemon.pikminbloom

   方法 B — Xposed + TrustMeAlready：
     在 LDPlayer 啟用 Root + Xposed，安裝 TrustMeAlready 模組

6. 開遊戲，在地圖上移動，log 自動寫入 pikmin_found.log
============================================================

安裝：
  pip install mitmproxy
"""

import json
import re
import os
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
    "1.1.1.1",  # 備用：有些版本用直接 IP
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

class MushroomSniffer:

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not self._is_niantic(host):
            return

        body = flow.response.get_content()
        if not body:
            return

        url = flow.request.pretty_url
        ctx.log.debug(f"[Sniffer] {flow.request.method} {url}  ({len(body)} bytes)")

        mushrooms = []

        # --- 嘗試 JSON 解析 ---
        try:
            data = json.loads(body)
            mushrooms = self._extract_from_json(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # --- 嘗試文字 regex（含 protobuf 裡的 UTF-8 字串）---
        if not mushrooms:
            try:
                text = body.decode("utf-8", errors="replace")
                mushrooms = self._extract_from_text(text, url)
            except Exception:
                pass

        # --- 若設定 dump_unknown 則存原始 binary ---
        if not mushrooms and getattr(ctx.options, "dump_unknown", False):
            fname = f"dump_{host.replace('.', '_')}_{len(body)}.bin"
            with open(fname, "wb") as f:
                f.write(body)
            ctx.log.info(f"[Dump] {fname}")

        for m in mushrooms:
            self._log_match(m, url)

    # -----------------------------------------------------------------------

    def _is_niantic(self, host: str) -> bool:
        return any(h in host for h in NIANTIC_HOSTS)

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

    def _extract_from_text(self, text: str, url: str):
        results = []
        # 在文字裡找 "Large Fire Mushroom" 等組合
        for size in SIZES:
            for mtype in ALL_MUSHROOM_TYPES:
                pattern = rf"\b{re.escape(size)}\s+{re.escape(mtype)}\s+Mushroom\b"
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    if not self._is_target(size, mtype):
                        continue
                    # 在前後 300 字元裡找座標（-XX.XXXXXX 格式）
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

    def _parse_name(self, name: str):
        upper = name.upper()
        size  = next((s for s in SIZES          if s.upper() in upper), None)
        mtype = next((t for t in ALL_MUSHROOM_TYPES if t.upper() in upper), None)
        return size, mtype

    def _is_target(self, size: str, mtype: str) -> bool:
        size_ok  = (size  in TARGET_SIZES) if TARGET_SIZES else True
        type_ok  = (mtype in TARGET_TYPES) if TARGET_TYPES else True
        return size_ok and type_ok

    def _log_match(self, m: dict, url: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        coord_str = (f"({m['lat']:.6f}, {m['lon']:.6f})"
                     if m.get("lat") is not None else "(座標未知)")
        entry = f"{ts}  [{m['size']} {m['type']}]  {coord_str}  raw={m['raw']!r}"
        ctx.log.warn(f"*** FOUND: {entry}")
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(entry + "\n")


addons = [MushroomSniffer()]

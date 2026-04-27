"""
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

安裝：
  pip install mitmproxy
Pikmin Bloom mitmproxy Sniffer
-------------------------------
直接攔截遊戲向 Niantic 伺服器請求的地圖資料，
無需截圖、OCR、template matching，速度快 10 倍以上。

使用方式：
  1. 安裝 mitmproxy：
       pip install mitmproxy

  2. 模擬器 WiFi 代理設為 <你的電腦 IP>:8080

  3. 安裝 mitmproxy CA 憑證到模擬器：
       mitmproxy 首次啟動後，瀏覽器打開 mitm.it 下載憑證
       adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/
       adb shell am start -n com.android.certinstaller/.CertInstallerMain \
           -a android.intent.action.VIEW \
           -d file:///sdcard/mitmproxy-ca-cert.pem

  4. 啟動 sniffer：
       mitmdump -s proxy_sniffer.py --ssl-insecure -p 8080

  5. 在模擬器中打開 Pikmin Bloom，移動地圖

  注意：
  - Niantic 有 SSL pinning，可能需要額外用 Frida 繞過
  - 違反 Niantic ToS，使用風險自負
  - 這是教育/研究用途

Frida SSL pinning bypass（需要 root 模擬器）：
  pip install frida-tools
  frida -U -f jp.pokemon.pokemongo -l ssl_pinning_bypass.js  # 替換成 Pikmin Bloom 的 package name
"""

import json
import re
from datetime import datetime
from mitmproxy import http

# 目標菇類型和大小
TARGET_SIZES = {"Large", "Giant"}
TARGET_TYPES = {"Fire", "Electric", "Water", "Crystal", "Poisonous"}

LOG_FILE = "proxy_found.log"

# Niantic API endpoint 關鍵字（實際路徑需抓包確認）
NIANTIC_ENDPOINTS = [
    "pikminbloom",
    "nianticlabs",
    "niantic",
]

# Size / Type 關鍵字對應（response 裡的 enum 值，需實際抓包後對應）
# 以下是推測值，需要你實際抓包後更新
SIZE_MAP = {
    1: "Small",
    2: "Normal",
    3: "Large",
    4: "Giant",
}

TYPE_MAP = {
    1: "Red",
    2: "Yellow",
    3: "Blue",
    4: "Fire",
    5: "Water",
    6: "Electric",
    7: "Poisonous",
    8: "Crystal",
    9: "White",
    10: "Pink",
    11: "Purple",
    12: "Gray",
}


def is_niantic_request(url: str) -> bool:
    return any(kw in url.lower() for kw in NIANTIC_ENDPOINTS)


def try_parse_mushroom(body: bytes, url: str):
    """
    嘗試從 response body 解析菇資料。
    body 可能是 JSON 或 protobuf，先試 JSON。
    """
    results = []

    # 試 JSON
    try:
        data = json.loads(body)
        results = parse_json_mushrooms(data)
        if results:
            return results
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # 試 protobuf（需要 betterproto 或 google.protobuf）
    # 如果你有 proto 定義，在這裡加 protobuf 解析
    # 暫時只印 hex 供分析用
    if b"mushroom" in body.lower() or b"Mushroom" in body:
        print(f"  [Proto?] 可能含菇資料，URL={url}, body hex={body[:80].hex()}")

    return results


def parse_json_mushrooms(data) -> list:
    """
    遞迴搜尋 JSON 裡含 mushroom 資訊的物件。
    結構不確定，先做通用搜尋。
    """
    results = []

    def search(obj):
        if isinstance(obj, dict):
            # 嘗試常見欄位名稱（需實際抓包後調整）
            keys_lower = {k.lower(): v for k, v in obj.items()}

            has_mushroom = any(
                "mushroom" in k or "kinoko" in k
                for k in keys_lower
            )
            if has_mushroom:
                lat = keys_lower.get("latitude") or keys_lower.get("lat")
                lon = keys_lower.get("longitude") or keys_lower.get("lon") or keys_lower.get("lng")
                size_raw = keys_lower.get("size") or keys_lower.get("mushroom_size")
                type_raw = keys_lower.get("type") or keys_lower.get("mushroom_type") or keys_lower.get("element")

                size = SIZE_MAP.get(size_raw, str(size_raw)) if isinstance(size_raw, int) else str(size_raw)
                mtype = TYPE_MAP.get(type_raw, str(type_raw)) if isinstance(type_raw, int) else str(type_raw)

                if lat and lon:
                    results.append({
                        "lat": lat, "lon": lon,
                        "size": size, "type": mtype,
                        "raw": obj,
                    })

            for v in obj.values():
                search(v)

        elif isinstance(obj, list):
            for item in obj:
                search(item)

    search(data)
    return results


class PikminSniffer:
    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url

        if not is_niantic_request(url):
            return

        body = flow.response.content
        if not body:
            return

        print(f"\n[API] {flow.request.method} {url[:80]}")
        print(f"      Status={flow.response.status_code}, Size={len(body)}B")

        mushrooms = try_parse_mushroom(body, url)
        if not mushrooms:
            return

        for m in mushrooms:
            size, mtype = m.get("size"), m.get("type")
            lat, lon = m.get("lat"), m.get("lon")

            marker = "***" if (size in TARGET_SIZES and mtype in TARGET_TYPES) else "   "
            line = f"{marker} [{size} {mtype}] ({lat}, {lon})"
            print(f"  {line}")

            if size in TARGET_SIZES and mtype in TARGET_TYPES:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(LOG_FILE, "a") as f:
                    f.write(f"{ts}  {line}\n")


addons = [PikminSniffer()]

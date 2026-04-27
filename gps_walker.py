"""
Pikmin Bloom GPS Walker
------------------------
只負責移動 GPS，不截圖、不 OCR、不 template match。
配合 proxy_sniffer.py 一起使用：

  Terminal 1（先啟動）：
    mitmdump -s proxy_sniffer.py --listen-port 8888 \\
      --set target_sizes=Large,Giant \\
      --set target_types=Fire,Electric,Water,Crystal,Poisonous

  Terminal 2：
    python gps_walker.py --bbox 25.03,121.53,25.04,121.54 --wait 2.5

每個點等 2–3 秒讓遊戲發出 API request 後繼續，比 scanner.py 快 5–10 倍。

安裝：
  pip install   （不需額外套件，只用標準庫 + adb）
"""

import subprocess
import time
import math
import argparse
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# GPS 路徑產生（與 scanner.py 相同邏輯）
# ---------------------------------------------------------------------------

def interpolate(lat1, lon1, lat2, lon2, step_m=300.0):
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    dist_m = math.sqrt(
        (dlat * 111320) ** 2 +
        (dlon * 111320 * math.cos(math.radians(lat1))) ** 2
    )
    if dist_m < step_m:
        return [(lat2, lon2)]
    n = max(1, int(dist_m / step_m))
    return [(lat1 + dlat * i / n, lon1 + dlon * i / n) for i in range(1, n + 1)]


def generate_grid(min_lat, min_lon, max_lat, max_lon, step_m=300.0):
    """蛇形掃描網格，step 預設 300m（比 scanner.py 的 500m 密，因為速度夠快）。"""
    spacing_deg = step_m / 111320.0
    points = []
    lat = min_lat
    col = 0
    while lat <= max_lat:
        lons = []
        lon = min_lon
        while lon <= max_lon:
            lons.append(lon)
            lon += spacing_deg
        if col % 2 == 1:
            lons = lons[::-1]
        for lon in lons:
            points.append((lat, lon))
        lat += spacing_deg
        col += 1
    return points


def parse_latlon(s):
    a, b = s.strip().split(",")
    return float(a), float(b)


def build_points(args):
    if args.mode == "line":
        lat1, lon1 = parse_latlon(args.start)
        lat2, lon2 = parse_latlon(args.end)
        return [(lat1, lon1)] + interpolate(lat1, lon1, lat2, lon2, args.step)
    elif args.mode == "grid":
        parts = [float(x) for x in args.bbox.split(",")]
        return generate_grid(parts[0], parts[1], parts[2], parts[3], args.step)
    elif args.mode == "route":
        segs = [parse_latlon(s) for s in args.route.split(";")]
        pts = [segs[0]]
        for i in range(len(segs) - 1):
            pts += interpolate(segs[i][0], segs[i][1],
                               segs[i+1][0], segs[i+1][1], args.step)
        return pts
    return []

# ---------------------------------------------------------------------------
# ADB
# ---------------------------------------------------------------------------

def get_device(device_id=None):
    if device_id:
        return device_id
    out = subprocess.check_output("adb devices", shell=True).decode()
    for line in out.splitlines()[1:]:
        if "\tdevice" in line:
            return line.split("\t")[0].strip()
    print("[Error] 找不到模擬器，請確認 ADB 已連接")
    sys.exit(1)


def set_gps(device_id, lat, lon):
    cmd = f"adb -s {device_id} emu geo fix {lon} {lat}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "OK" in result.stdout or result.returncode == 0

# ---------------------------------------------------------------------------
# 主走點迴圈
# ---------------------------------------------------------------------------

def walk(device_id, points, wait_sec=2.5, skip=0):
    if skip > 0:
        print(f"[Skip] 從第 {skip+1} 點繼續")
        points = points[skip:]

    total = len(points)
    est_min = total * wait_sec / 60
    print(f"\n{'='*50}")
    print(f"  路徑點數：{total}")
    print(f"  等待時間：{wait_sec}s / 點")
    print(f"  預估時間：{est_min:.1f} 分鐘")
    print(f"  確認 mitmdump 已在另一個 Terminal 執行中")
    print(f"{'='*50}\n")

    for i, (lat, lon) in enumerate(points):
        ok = set_gps(device_id, lat, lon)
        ts = datetime.now().strftime("%H:%M:%S")
        status = "✓" if ok else "✗"
        print(f"[{ts}] [{i+skip+1:4d}/{total+skip}] {lat:.6f}, {lon:.6f}  {status}")
        time.sleep(wait_sec)

    print(f"\n[完成] 所有點掃描完畢，結果在 proxy_sniffer 的 log 裡。")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Pikmin Bloom GPS Walker — 配合 proxy_sniffer.py 使用"
    )
    p.add_argument("--device", default=None, help="ADB 裝置 ID（不填自動偵測）")
    p.add_argument("--mode", default="grid", choices=["line", "grid", "route"])
    p.add_argument("--step", type=float, default=300.0,
                   help="GPS 點間距（公尺，預設 300）")
    p.add_argument("--wait", type=float, default=2.5,
                   help="每個點等待秒數（讓遊戲發出 API request，預設 2.5）")
    p.add_argument("--skip", type=int, default=0,
                   help="跳過前 N 個點（斷點續掃）")

    p.add_argument("--start",  default=None, help="line 模式起點 lat,lon")
    p.add_argument("--end",    default=None, help="line 模式終點 lat,lon")
    p.add_argument("--bbox",   default=None,
                   help="grid 模式範圍 min_lat,min_lon,max_lat,max_lon")
    p.add_argument("--route",  default=None,
                   help="route 模式路徑點 lat,lon;lat,lon;...")

    args = p.parse_args()

    if args.mode == "line" and (not args.start or not args.end):
        p.error("line 模式需要 --start 和 --end")
    if args.mode == "grid" and not args.bbox:
        p.error("grid 模式需要 --bbox")
    if args.mode == "route" and not args.route:
        p.error("route 模式需要 --route")

    device_id = get_device(args.device)
    print(f"[ADB] 裝置: {device_id}")

    points = build_points(args)
    if not points:
        print("[Error] 沒有產生任何路徑點")
        sys.exit(1)

    walk(device_id, points, wait_sec=args.wait, skip=args.skip)


if __name__ == "__main__":
    main()

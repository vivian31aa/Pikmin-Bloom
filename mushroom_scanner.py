#!/usr/bin/env python3
"""
Pikmin Bloom large mushroom world scanner (Frida memory edition)
────────────────────────────────────────────────────────────────
流程：
  1. ADB emu geo fix 移動 GPS
  2. 等遊戲載入（動態偵測：掃到的菇數穩定才算載入完成）
  3. 呼叫 Frida RPC scanMushrooms → 取得本區菇座標
  4. 過濾 large (size=3)，記錄到 JSON
  5. 移到下一格

使用方式：
  python3 mushroom_scanner.py                      # 掃預設城市列表
  python3 mushroom_scanner.py --lat 35.6 --lon 139.7 --range 0.1 --step 0.005
  python3 mushroom_scanner.py --cities Tokyo London # 只掃指定城市

需求：
  pip install frida
  adb -s emulator-5554 連線正常
  emulator 已執行 Pikmin Bloom + frida-server
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import frida

# ── 設定 ────────────────────────────────────────────────────────────────────
DEVICE_SERIAL  = "emulator-5554"
FRIDA_HOST     = "127.0.0.1:27042"
FRIDA_SCRIPT   = Path(__file__).parent / "frida_hook.js"
OUTPUT_FILE    = Path(__file__).parent / "large_mushrooms.json"

LOAD_WAIT_MIN  = 8     # 移動後最少等待秒數
LOAD_WAIT_MAX  = 25    # 等待上限
STABLE_CHECKS  = 3     # 連續幾次掃描結果相同才算穩定
STABLE_INTERVAL= 2.0   # 每次穩定檢查間隔秒
STABLE_MIN_COUNT = 5   # 至少掃到這麼多才算 stable（避免還在載入就退出）

SCAN_RADIUS    = 0.003  # 單次掃描半徑 (度，約 300m)
DEFAULT_STEP   = 0.005  # 格點間距 (度，約 500m；確保覆蓋重疊)
DEFAULT_RANGE  = 0.05   # 城市掃描半徑 (度，約 5km)

COLOR_LABEL = {
    2: "red", 6: "yellow", 9: "pink/electric",
    11: "fire", 13: "crystal", 18: "poisonous",
}
SIZE_LABEL = {1: "small", 2: "normal", 3: "large"}

# 預設城市清單 (lat, lon, name)
CITIES = [
    (35.6762, 139.6503, "Tokyo"),
    (51.5074, -0.1278,  "London"),
    (48.8566,  2.3522,  "Paris"),
    (40.7128, -74.0060, "New York"),
    (37.7749,-122.4194, "San Francisco"),
    (22.3193, 114.1694, "Hong Kong"),
    ( 1.3521, 103.8198, "Singapore"),
    (48.1351,  11.5820, "Munich"),
    (-33.8688,151.2093, "Sydney"),
    (55.7558,  37.6173, "Moscow"),
    (25.0330, 121.5654, "Taipei"),
    (37.5665, 126.9780, "Seoul"),
    (31.2304, 121.4737, "Shanghai"),
    (28.6139,  77.2090, "Delhi"),
    (-23.5505, -46.6333,"Sao Paulo"),
    (19.4326, -99.1332, "Mexico City"),
    (52.5200,  13.4050, "Berlin"),
    (41.9028,  12.4964, "Rome"),
    (59.9311,  30.3609, "Saint Petersburg"),
    (35.1796, 129.0756, "Busan"),
]

# ── ADB / GPS ────────────────────────────────────────────────────────────────
def adb(*args):
    return subprocess.run(
        ["adb", "-s", DEVICE_SERIAL, *args],
        capture_output=True, text=True
    )

def set_gps(lat: float, lon: float):
    # emu geo fix takes (longitude, latitude) order
    adb("emu", "geo", "fix", str(lon), str(lat))

# ── Frida 連線 ───────────────────────────────────────────────────────────────
PIKMIN_PKG = "com.nianticlabs.pikminbloom"

def connect_frida():
    device = frida.get_device_manager().add_remote_device(FRIDA_HOST)

    # 優先：直接用 package name attach（最快、最穩定）
    try:
        session = device.attach(PIKMIN_PKG)
        script = session.create_script(FRIDA_SCRIPT.read_text())
        script.load()
        print(f"[+] 已附加到 {PIKMIN_PKG}")
        return session, script
    except frida.ProcessNotFoundError:
        pass
    except Exception as e:
        print(f"[!] package name attach 失敗: {e}，改用 enumerate_processes...")

    # 備用：enumerate_processes（比 enumerate_applications 快，不需 scope="full"）
    for proc in device.enumerate_processes():
        name = proc.name.lower()
        if "pikmin" in name or "nianticlabs" in name:
            try:
                session = device.attach(proc.pid)
                script = session.create_script(FRIDA_SCRIPT.read_text())
                script.load()
                print(f"[+] 已附加到 {proc.name} (pid {proc.pid})")
                return session, script
            except Exception as e:
                print(f"[!] 附加 pid {proc.pid} 失敗: {e}")

    raise RuntimeError(
        f"找不到 Pikmin Bloom 程序。\n"
        f"請確認：\n"
        f"  1. 遊戲正在執行中\n"
        f"  2. frida-server 已在 emulator 上啟動\n"
        f"  3. adb forward tcp:{FRIDA_HOST.split(':')[1]} tcp:{FRIDA_HOST.split(':')[1]} 已執行\n"
        f"  手動確認：frida-ps -H {FRIDA_HOST} | grep -i pikmin"
    )

# ── 掃描 + 動態等載入 ─────────────────────────────────────────────────────────
def scan_with_wait(script, lat: float, lon: float) -> list:
    """
    移動後動態等待載入：每隔 STABLE_INTERVAL 掃一次，
    連續 STABLE_CHECKS 次結果的 mushroom 數量相同且 > 0 → 視為載入完成。
    最少等 LOAD_WAIT_MIN 秒，最多 LOAD_WAIT_MAX 秒。
    """
    time.sleep(LOAD_WAIT_MIN)

    counts = []
    deadline = time.time() + (LOAD_WAIT_MAX - LOAD_WAIT_MIN)
    last_results = []
    attempt = 0

    while time.time() < deadline:
        attempt += 1
        try:
            raw = script.exports.scan_mushrooms(lat, lon, SCAN_RADIUS)
            results = json.loads(raw)
            err = None
        except Exception as e:
            results = []
            err = e

        sizes = [r.get("size") for r in results]
        n_large = sizes.count(3)
        print(f"\n    RPC#{attempt}: total={len(results)} large={n_large}"
              + (f" err={err}" if err else ""), end="", flush=True)

        counts.append(len(results))
        last_results = results

        # 穩定條件：最近 N 次計數相同 且 count >= STABLE_MIN_COUNT
        if len(counts) >= STABLE_CHECKS:
            recent = counts[-STABLE_CHECKS:]
            if len(set(recent)) == 1 and recent[0] >= STABLE_MIN_COUNT:
                print(" [stable]", flush=True)
                break

        time.sleep(STABLE_INTERVAL)

    if not last_results:
        print(" [timeout/empty]", flush=True)
    return last_results

# ── 格點生成 ──────────────────────────────────────────────────────────────────
def grid_points(center_lat, center_lon, range_deg, step_deg):
    points = []
    lat = center_lat - range_deg
    while lat <= center_lat + range_deg + 1e-9:
        lon = center_lon - range_deg
        while lon <= center_lon + range_deg + 1e-9:
            points.append((round(lat, 6), round(lon, 6)))
            lon += step_deg
        lat += step_deg
    return points

# ── 主程式 ────────────────────────────────────────────────────────────────────
def main():
    global LOAD_WAIT_MIN
    parser = argparse.ArgumentParser(description="Pikmin Bloom large mushroom Frida scanner")
    parser.add_argument("--cities", nargs="*", help="城市名稱篩選（空格分隔，預設掃全部）")
    parser.add_argument("--lat",   type=float, help="自訂中心緯度（與 --lon 搭配）")
    parser.add_argument("--lon",   type=float, help="自訂中心經度")
    parser.add_argument("--range", type=float, default=DEFAULT_RANGE, help=f"掃描半徑(度) 預設{DEFAULT_RANGE}")
    parser.add_argument("--step",  type=float, default=DEFAULT_STEP,  help=f"格點間距(度) 預設{DEFAULT_STEP}")
    parser.add_argument("--wait",  type=float, default=LOAD_WAIT_MIN, help=f"最短等待秒數 預設{LOAD_WAIT_MIN}")
    parser.add_argument("--debug", action="store_true", help="顯示每格掃描的原始 size/crystal 分布")
    parser.add_argument("--output", default=str(OUTPUT_FILE))
    args = parser.parse_args()

    LOAD_WAIT_MIN = args.wait

    # 決定掃描目標列表
    if args.lat is not None and args.lon is not None:
        targets = [(args.lat, args.lon, f"custom({args.lat},{args.lon})")]
    else:
        targets = CITIES
        if args.cities:
            names = {c.lower() for c in args.cities}
            targets = [c for c in targets if c[2].lower() in names]
            if not targets:
                print("[-] 找不到指定城市，可用城市：" + ", ".join(c[2] for c in CITIES))
                sys.exit(1)

    output_path = Path(args.output)
    # 載入已有結果（支援斷點續掃）；用 4 位小數做 key（精度≈11m，容忍同菇座標微差）
    seen: dict = {}
    if output_path.exists():
        try:
            for m in json.loads(output_path.read_text()):
                seen[f"{m['lat']:.4f},{m['lon']:.4f}"] = m
            print(f"[*] 載入已有 {len(seen)} 筆記錄")
        except Exception:
            pass

    # 連接 Frida
    session, script = connect_frida()

    total_new = 0
    try:
        for city_lat, city_lon, city_name in targets:
            points = grid_points(city_lat, city_lon, args.range, args.step)
            print(f"\n[*] {city_name}  格點數={len(points)}")

            for idx, (lat, lon) in enumerate(points, 1):
                print(f"  [{idx}/{len(points)}] ({lat:.4f}, {lon:.4f})", end="  ", flush=True)
                set_gps(lat, lon)

                try:
                    results = scan_with_wait(script, lat, lon)
                except Exception as e:
                    print(f"掃描錯誤: {e}")
                    continue

                # debug: 顯示 size 分布
                if args.debug and results:
                    from collections import Counter
                    size_dist = Counter(r.get("size") for r in results)
                    crystal_dist = Counter(r.get("crystal") for r in results)
                    print(f"\n    [debug] total={len(results)} size={dict(size_dist)} crystal={dict(crystal_dist)}")
                    for r in results:
                        if r.get("size") == 3:
                            print(f"    [debug] large: {r}")

                # 只保留 large (size=3)，濾掉假陽性（crystal 只能是 1 或 4）
                large = [
                    r for r in results
                    if r.get("size") == 3
                    and r.get("crystal") in (1, 4)
                ]
                new_count = 0
                for m in large:
                    # 4 位小數 key ≈ 11m，同菇不同 copy 會被去重
                    key = f"{m['lat']:.4f},{m['lon']:.4f}"
                    if key not in seen:
                        m["city"] = city_name
                        m["colorName"] = COLOR_LABEL.get(m.get("colorId", 0), str(m.get("colorId", "?")))
                        seen[key] = m
                        new_count += 1
                        total_new += 1

                if large:
                    print(f"找到 {len(large)} 個 large (+{new_count} 新)  "
                          + " | ".join(f"{COLOR_LABEL.get(m.get('colorId',0),'?')}@({m['lat']:.5f},{m['lon']:.5f})"
                                       for m in large[:3])
                          + (" ..." if len(large) > 3 else ""))
                else:
                    print("無 large")

                # 每格掃完就存檔（斷點保護）
                output_path.write_text(json.dumps(list(seen.values()), indent=2, ensure_ascii=False))

    except KeyboardInterrupt:
        print("\n[!] 使用者中斷")
    finally:
        session.detach()
        print(f"\n[*] 共新增 {total_new} 個 large mushroom，總計 {len(seen)} 筆")
        print(f"[*] 已儲存至 {output_path}")


if __name__ == "__main__":
    main()

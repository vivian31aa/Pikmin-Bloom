"""
Pikmin Bloom Walk & Scan v2
----------------------------
流程：
  1. GPS 跳到下一個點
  2. 動態等地圖穩定（不再死等 15s）
  3. 截圖，用 template matching 找地圖上所有目標菇
  4. 逐一點擊，等 popup 出現後截圖
  5. 用 OCR 讀標題確認 Size + Type
  6. 符合就記錄座標

目標格式：[Size] [Type] Mushroom
  Size: Small / Normal / Large / Giant
  Type: Fire / Electric / Water / Crystal / Poisonous / ...

安裝：
  pip install opencv-python numpy pytesseract pillow
  brew install tesseract   # macOS
  # Windows: 下載 Tesseract installer，見 README
"""

import subprocess
import time
import math
import argparse
import sys
import os
import re
import hashlib
from datetime import datetime

import cv2
import numpy as np

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    print("[Warning] pytesseract 未安裝，將跳過 Size 確認，只靠 template type 過濾")

# ---------------------------------------------------------------------------
# 目標設定
# ---------------------------------------------------------------------------

TARGET_SIZES = ["Large", "Giant"]
TARGET_TYPES = ["Fire", "Electric", "Water", "Crystal", "Poisonous"]

ALL_MUSHROOM_TYPES = [
    "Fire", "Crystal", "Electric", "Water", "Poisonous",
    "Red", "Yellow", "Blue", "Purple", "White", "Pink", "Gray",
    "Lavish", "Giant",
]
SIZES = ["Small", "Normal", "Large", "Giant"]

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

# ---------------------------------------------------------------------------
# Template 載入
# ---------------------------------------------------------------------------

def load_templates(target_types=None):
    """只載入目標 type 的 template，省略不必要的匹配。"""
    templates = {}
    if not os.path.exists(TEMPLATE_DIR):
        print(f"[Warning] 找不到 templates/：{TEMPLATE_DIR}")
        return templates

    want = {t.lower() for t in target_types} if target_types else None
    for fname in os.listdir(TEMPLATE_DIR):
        if not fname.endswith(".png"):
            continue
        name = fname.replace(".png", "").lower()
        if want and name not in want:
            continue
        img = cv2.imread(os.path.join(TEMPLATE_DIR, fname))
        if img is not None:
            templates[name] = img
            print(f"  [Template] {name}: {img.shape}")
    return templates

# ---------------------------------------------------------------------------
# ADB 工具
# ---------------------------------------------------------------------------

def run_adb(device_id, cmd, timeout=10):
    full = f"adb -s {device_id} {cmd}"
    try:
        return subprocess.check_output(full, shell=True, timeout=timeout,
                                       stderr=subprocess.DEVNULL)
    except Exception as e:
        raise RuntimeError(f"ADB error: {e}")


def get_device(device_id=None):
    if device_id:
        return device_id
    out = subprocess.check_output("adb devices", shell=True).decode()
    for line in out.splitlines()[1:]:
        if "\tdevice" in line:
            return line.split("\t")[0].strip()
    print("[Error] 找不到模擬器")
    sys.exit(1)


def set_gps(device_id, lat, lon):
    cmd = f"adb -s {device_id} emu geo fix {lon} {lat}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "OK" in result.stdout or result.returncode == 0


CANONICAL_W, CANONICAL_H = 1080, 2400


def screencap(device_id):
    raw = subprocess.check_output(
        f"adb -s {device_id} exec-out screencap -p",
        shell=True, timeout=15,
    )
    arr = np.frombuffer(raw, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise RuntimeError("截圖失敗")
    if img.shape[0] != CANONICAL_H or img.shape[1] != CANONICAL_W:
        img = cv2.resize(img, (CANONICAL_W, CANONICAL_H))
    return img


def tap(device_id, x, y):
    run_adb(device_id, f"shell input tap {x} {y}")


def back(device_id):
    run_adb(device_id, "shell input keyevent 4")


def _frame_hash(img):
    h, w = img.shape[:2]
    roi = img[int(h*0.15):int(h*0.80), int(w*0.1):int(w*0.9)]
    small = cv2.resize(roi, (64, 64))
    return hashlib.md5(small.tobytes()).hexdigest()

# ---------------------------------------------------------------------------
# 動態等待：取代固定 time.sleep(N)
# ---------------------------------------------------------------------------

def wait_map_stable(device_id, stable_sec=1.5, timeout=20.0, poll=1.0):
    """
    輪詢截圖直到畫面連續 stable_sec 無變化，表示地圖已載入完成。
    比死等 15s 平均快 2–3 倍。
    """
    deadline = time.time() + timeout
    prev_hash = None
    stable_since = None

    while time.time() < deadline:
        try:
            img = screencap(device_id)
        except Exception:
            time.sleep(poll)
            continue

        if check_and_dismiss_network_error_img(device_id, img):
            stable_since = None
            prev_hash = None
            time.sleep(2.0)
            continue

        h = _frame_hash(img)
        if h == prev_hash:
            if stable_since and (time.time() - stable_since) >= stable_sec:
                return img
        else:
            stable_since = time.time()
        prev_hash = h
        time.sleep(poll)

    return screencap(device_id)


def wait_popup(device_id, timeout=8.0, poll=0.5):
    """
    輪詢等待 popup 出現，找到立刻回傳，比 sleep(5) 平均省 2–4 秒。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            img = screencap(device_id)
            popup = find_popup(img)
            if popup is not None:
                return img, popup
        except Exception:
            pass
        time.sleep(poll)
    img = screencap(device_id)
    return img, None

# ---------------------------------------------------------------------------
# Network Error 偵測
# ---------------------------------------------------------------------------

def check_and_dismiss_network_error_img(device_id, img):
    """接受已截好的圖，省一次 screencap。"""
    h, w = img.shape[:2]
    mid = img[int(h*0.40):int(h*0.80), int(w*0.05):int(w*0.95)]
    gray = cv2.cvtColor(mid, cv2.COLOR_BGR2GRAY)
    white_ratio = np.sum(gray > 240) / gray.size

    is_err = white_ratio > 0.55
    if not is_err and OCR_AVAILABLE:
        pil = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        text = pytesseract.image_to_string(pil)
        is_err = "Network Error" in text or "Failed to communicate" in text

    if is_err:
        print(f"  [!] Network Error，點擊 Retry...")
        run_adb(device_id, f"shell input tap {w//2} {int(h*0.5925)}")
        return True
    return False

# ---------------------------------------------------------------------------
# Template Matching：找地圖上的菇
# ---------------------------------------------------------------------------

def find_mushrooms_on_map(img, templates, threshold=0.60):
    """
    只匹配目標 type 的 template（templates 已在載入時過濾）。
    回傳 list of (cx, cy, type_name, score)
    """
    found = []
    img_h, img_w = img.shape[:2]

    y_min = int(img_h * 0.08)
    y_max = int(img_h * 0.85)
    roi = img[y_min:y_max, 0:img_w]
    gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)

    type_threshold = {
        "electric":  0.62,
        "fire":      0.79,
        "water":     0.43,
        "crystal":   0.55,
        "poisonous": 0.55,
    }

    for name, tmpl in templates.items():
        t = type_threshold.get(name, threshold)
        for scale in [0.9, 1.0, 1.1, 1.2, 1.3, 1.4, 1.5]:
            h = int(tmpl.shape[0] * scale)
            w = int(tmpl.shape[1] * scale)
            if h > roi.shape[0] or w > roi.shape[1] or h < 10 or w < 10:
                continue
            resized = cv2.resize(tmpl, (w, h))
            gray_tmpl = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)

            result = cv2.matchTemplate(gray, gray_tmpl, cv2.TM_CCOEFF_NORMED)
            locs = np.where(result >= t)

            for pt in zip(*locs[::-1]):
                cx = pt[0] + w // 2
                cy = pt[1] + h // 2 + y_min
                score = result[pt[1], pt[0]]

                duplicate = False
                for i, (fx, fy, fn, fs) in enumerate(found):
                    if abs(fx - cx) < 100 and abs(fy - cy) < 100:
                        if score > fs:
                            found[i] = (cx, cy, name, float(score))
                        duplicate = True
                        break
                if not duplicate:
                    found.append((cx, cy, name, float(score)))

    return found

# ---------------------------------------------------------------------------
# OCR：讀 popup 標題
# ---------------------------------------------------------------------------

def find_popup(img):
    h, w = img.shape[:2]
    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    mask = cv2.inRange(hsv, np.array([0, 0, 0]), np.array([180, 255, 60]))
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    best, best_area = None, 0
    for c in contours:
        x, y, cw, ch = cv2.boundingRect(c)
        area = cw * ch
        if cw > w * 0.25 and ch > h * 0.03 and area > best_area:
            best, best_area = (x, y, cw, ch), area

    if best:
        x, y, cw, ch = best
        return img[y:y+ch, x:x+cw]
    return None


def read_size_from_popup(popup):
    """
    從 popup 影像用 OCR 讀出標題文字，回傳 (size, type) 字串或 (None, None)。
    """
    if not OCR_AVAILABLE or popup is None:
        return None, None
    pil = Image.fromarray(cv2.cvtColor(popup, cv2.COLOR_BGR2RGB))
    pil_large = pil.resize((pil.width * 3, pil.height * 3), Image.LANCZOS)
    text = pytesseract.image_to_string(pil_large)
    return parse_mushroom_title(text.strip())


def parse_mushroom_title(text):
    """
    從 OCR 文字抓出 Size 和 Type。
    例如 'Giant Fire Mushroom' -> ('Giant', 'Fire')
    """
    text_upper = text.upper()
    found_size = next((s for s in SIZES if s.upper() in text_upper), None)
    found_type = next((t for t in ALL_MUSHROOM_TYPES if t.upper() in text_upper), None)
    return found_size, found_type


def is_target(size, mtype, target_sizes, target_types):
    size_ok = (size in target_sizes) if target_sizes else True
    type_ok = (mtype in target_types) if target_types else True
    return size_ok and type_ok

# ---------------------------------------------------------------------------
# GPS 路徑產生
# ---------------------------------------------------------------------------

def interpolate(lat1, lon1, lat2, lon2, step_m=500.0):
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


def generate_grid(min_lat, min_lon, max_lat, max_lon, step_m=500.0):
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
# 主掃描迴圈
# ---------------------------------------------------------------------------

def walk_and_scan(device_id, points, target_sizes, target_types,
                  templates, step_m=500.0, map_load_wait=20.0,
                  save_ss=False, log_path="pikmin_found.log"):

    total = len(points)
    results = []
    # 動態等待比死等快，預估時間僅供參考
    est_min = total * (map_load_wait * 0.5 + 4) / 60

    print(f"\n{'='*55}")
    print(f"  目標大小：{', '.join(target_sizes) if target_sizes else '全部'}")
    print(f"  目標類型：{', '.join(target_types) if target_types else '全部'}")
    print(f"  路徑點數：{total}")
    print(f"  最長等待：{map_load_wait}s/點（動態，通常更快）")
    print(f"  Templates：{list(templates.keys())}")
    print(f"  預估時間：{est_min:.0f} 分鐘")
    print(f"{'='*55}\n")

    for i, (lat, lon) in enumerate(points):
        ok = set_gps(device_id, lat, lon)
        print(f"\n[{i+1:4d}/{total}] GPS {lat:.6f}, {lon:.6f}  {'✓' if ok else '✗'}")

        # 動態等地圖穩定，最多等 map_load_wait 秒
        map_img = wait_map_stable(device_id, stable_sec=1.5,
                                  timeout=map_load_wait, poll=1.0)

        if save_ss:
            ts = datetime.now().strftime("%H%M%S")
            cv2.imwrite(f"ss_{ts}_map.png", map_img)

        if templates:
            mushrooms = find_mushrooms_on_map(map_img, templates)
        else:
            mushrooms = []

        if not mushrooms:
            print(f"  地圖上沒有偵測到目標菇圖示")
            continue

        print(f"  偵測到 {len(mushrooms)} 個菇圖示，逐一確認...")

        for j, (cx, cy, tmpl_name, score) in enumerate(mushrooms):
            print(f"  [{j+1}/{len(mushrooms)}] 點擊 ({cx},{cy}) type={tmpl_name} score={score:.2f}")

            tap(device_id, cx, cy)

            # 動態等 popup
            _, popup = wait_popup(device_id, timeout=8.0, poll=0.5)

            if popup is None:
                print(f"    Popup 未出現，略過")
                back(device_id)
                continue

            size, mtype = read_size_from_popup(popup)
            print(f"    解析: size={size}, type={mtype}")

            if save_ss:
                ts = datetime.now().strftime("%H%M%S")
                cv2.imwrite(f"ss_{ts}_pt{i}_m{j}_popup.png", popup)

            if is_target(size, mtype, target_sizes, target_types):
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                entry = (f"{ts}  [{size} {mtype}]  "
                         f"({lat:.6f}, {lon:.6f})  screen=({cx},{cy})")
                print(f"  *** FOUND: {entry}")
                with open(log_path, "a") as f:
                    f.write(entry + "\n")
                results.append({"time": ts, "size": size, "type": mtype,
                                 "lat": lat, "lon": lon})
            else:
                print(f"    不是目標菇，略過")

            # 關閉 popup：點左上方安全區域
            h_img, w_img = CANONICAL_H, CANONICAL_W
            run_adb(device_id, f"shell input tap 60 {int(h_img * 0.45)}")
            time.sleep(0.5)

    print(f"\n{'='*55}")
    print(f"  完成！共發現 {len(results)} 個目標菇。")
    if results:
        print(f"  紀錄檔：{log_path}")
    print(f"{'='*55}\n")
    return results

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Pikmin Bloom Walk & Scan v2")
    p.add_argument("--device",       default=None)
    p.add_argument("--mode",         default="grid",
                   choices=["line", "grid", "route"])
    p.add_argument("--target-sizes", nargs="+", default=["Large"],
                   choices=SIZES)
    p.add_argument("--target-types", nargs="+",
                   default=["Fire", "Electric", "Water", "Crystal", "Poisonous"],
                   choices=ALL_MUSHROOM_TYPES)
    p.add_argument("--step",      type=float, default=500.0,
                   help="每個 GPS 點之間的距離（公尺）")
    p.add_argument("--wait",      type=float, default=20.0,
                   help="地圖載入最長等待秒數（動態偵測，通常更快）")
    p.add_argument("--threshold", type=float, default=0.60,
                   help="Template matching 門檻（0~1）")
    p.add_argument("--save-ss",   action="store_true",
                   help="儲存截圖供除錯")
    p.add_argument("--log",       default="pikmin_found.log")
    p.add_argument("--skip",      type=int, default=0,
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

    print("[Templates] 載入模板...")
    templates = load_templates(args.target_types)
    if not templates:
        print("[Warning] 沒有載入任何 template，將跳過地圖偵測（只依賴 OCR）")

    points = build_points(args)
    if not points:
        print("[Error] 沒有產生任何路徑點")
        sys.exit(1)

    if args.skip > 0:
        print(f"[Skip] 跳過前 {args.skip} 個點，從第 {args.skip+1} 點開始")
        points = points[args.skip:]

    walk_and_scan(
        device_id    = device_id,
        points       = points,
        target_sizes = args.target_sizes,
        target_types = args.target_types,
        templates    = templates,
        step_m       = args.step,
        map_load_wait= args.wait,
        save_ss      = args.save_ss,
        log_path     = args.log,
    )


if __name__ == "__main__":
    main()

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
            continue  # 跳過不是目標 type 的 template
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
    # 取地圖中央區塊計算 hash，忽略動態 UI
    h, w = img.shape[:2]
    roi = img[int(h*0.15):int(h*0.80), int(w*0.1):int(w*0.9)]
    small = cv2.resize(roi, (64, 64))
    return hashlib.md5(small.tobytes()).hexdigest()

# ---------------------------------------------------------------------------
# 動態等待：取代 time.sleep(N)
# ---------------------------------------------------------------------------

def wait_map_stable(device_id, stable_sec=1.5, timeout=20.0, poll=1.0):
    """
    輪詢截圖，連續 stable_sec 內畫面不變就認定載入完成。
    最多等 timeout 秒，比死等 15s 平均快 2–3 倍。
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
                return img  # 地圖穩定，回傳最新截圖
        else:
            stable_since = time.time()
        prev_hash = h
        time.sleep(poll)

    return screencap(device_id)  # timeout → 直接截圖


def wait_popup(device_id, timeout=8.0, poll=0.5):
    """
    輪詢等待 popup 出現（取代 sleep(5)）。
    找到就立刻回傳，平均省 2–4 秒。
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
    return screencap(device_id), None

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
# Template Matching
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
# OCR：只讀標題列
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
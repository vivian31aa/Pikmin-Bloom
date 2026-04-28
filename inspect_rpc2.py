import struct
import re
import sys

path = "niantic_dumps/1777346035338_ichigo-rel_nianticlabs_com_rpc2_315824.bin"
if len(sys.argv) > 1:
    path = sys.argv[1]

with open(path, "rb") as f:
    data = f.read()

print(f"Size: {len(data)} bytes")
print()

# -----------------------------------------------------------------------
# 1. 搜尋 double lat (20-27) 和 double lon (118-125)
# -----------------------------------------------------------------------
lat_d, lon_d = [], []
for i in range(0, len(data) - 7):
    v = struct.unpack_from("<d", data, i)[0]
    if 20.0 <= v <= 27.0:
        lat_d.append((i, v))
    elif 118.0 <= v <= 125.0:
        lon_d.append((i, v))

print(f"Double lat(20-27): {len(lat_d)}  Double lon(118-125): {len(lon_d)}")

# -----------------------------------------------------------------------
# 2. 搜尋 int32 scaled by 1e7
#    Taiwan lat  *1e7 = 200_000_000 ~ 270_000_000
#    Taiwan lon  *1e7 = 1_180_000_000 ~ 1_250_000_000
# -----------------------------------------------------------------------
lat_i, lon_i = [], []
for i in range(0, len(data) - 3):
    v = struct.unpack_from("<i", data, i)[0]
    if 200_000_000 <= v <= 270_000_000:
        lat_i.append((i, v / 1e7))
    elif 1_180_000_000 <= v <= 1_250_000_000:
        lon_i.append((i, v / 1e7))

print(f"Int32*1e7 lat:    {len(lat_i)}  Int32*1e7 lon:    {len(lon_i)}")

# -----------------------------------------------------------------------
# 3. 配對：同一格式，距離 <= 200 bytes
# -----------------------------------------------------------------------
def find_pairs(lats, lons, window=200, label=""):
    pairs = []
    for lo, lv in lats:
        for no, nv in lons:
            if abs(no - lo) <= window:
                pairs.append((lo, no, lv, nv, abs(no - lo)))
    pairs.sort(key=lambda x: x[0])
    if pairs:
        print(f"\n=== Pairs ({label}, window={window}) ===")
        seen = set()
        for lo, no, lv, nv, d in pairs:
            key = (round(lv, 3), round(nv, 3))
            if key in seen:
                continue
            seen.add(key)
            print(f"  lat={lv:.6f}  lon={nv:.6f}  "
                  f"(lat_off={lo}, lon_off={no}, dist={d})")
            # 顯示周圍 bytes
            start = max(0, min(lo, no) - 8)
            end   = min(len(data), max(lo, no) + 16)
            ctx   = data[start:end]
            print(f"    hex: {ctx.hex()}")
            # 小整數可能是 type/size enum
            small = []
            for j in range(0, len(ctx) - 3, 1):
                vi = struct.unpack_from("<I", ctx, j)[0]
                if 1 <= vi <= 20:
                    small.append((start + j, vi))
            if small:
                print(f"    small ints (enum?): {small[:8]}")
    return pairs

p1 = find_pairs(lat_d, lon_d, window=200, label="double+double")
p2 = find_pairs(lat_i, lon_i, window=200, label="int32*1e7")
p3 = find_pairs(lat_d, lon_i, window=200, label="double lat + int32 lon")
p4 = find_pairs(lat_i, lon_d, window=200, label="int32 lat + double lon")

total = len(p1) + len(p2) + len(p3) + len(p4)
if total == 0:
    print("\nNo pairs in any format. Printing all candidates:")
    print("\nDouble lats:")
    for o, v in lat_d[:15]:
        print(f"  off={o:7d}  {v:.6f}")
    print("\nDouble lons:")
    for o, v in lon_d[:10]:
        print(f"  off={o:7d}  {v:.6f}")
    print("\nInt32*1e7 lats:")
    for o, v in lat_i[:15]:
        print(f"  off={o:7d}  {v:.6f}")
    print("\nInt32*1e7 lons:")
    for o, v in lon_i[:15]:
        print(f"  off={o:7d}  {v:.6f}")

import struct
import re
import sys

path = "niantic_dumps/1777346035338_ichigo-rel_nianticlabs_com_rpc2_315824.bin"
if len(sys.argv) > 1:
    path = sys.argv[1]

with open(path, "rb") as f:
    data = f.read()

print(f"Size: {len(data)} bytes")
print(f"First 16 bytes: {data[:16].hex()}")
print()

# 掃描所有可能是 Taiwan lat/lon 的 double（步距 1 byte 避免遺漏）
LAT_MIN, LAT_MAX = 20.0, 27.0     # Taiwan lat
LON_MIN, LON_MAX = 118.0, 124.0   # Taiwan lon

lat_offsets = []
lon_offsets = []

for i in range(0, len(data) - 7):
    v = struct.unpack_from("<d", data, i)[0]
    if LAT_MIN <= v <= LAT_MAX:
        lat_offsets.append((i, v))
    elif LON_MIN <= v <= LON_MAX:
        lon_offsets.append((i, v))

print(f"Taiwan lat candidates: {len(lat_offsets)}")
print(f"Taiwan lon candidates: {len(lon_offsets)}")
print()

# 配對：找 lat 附近 ±32 bytes 內有沒有 lon
print("=== Coordinate Pairs ===")
pairs = []
for lat_off, lat_val in lat_offsets:
    for lon_off, lon_val in lon_offsets:
        dist = abs(lon_off - lat_off)
        if dist <= 32:
            pairs.append((lat_off, lon_off, lat_val, lon_val, dist))

pairs.sort(key=lambda x: x[0])
for lat_off, lon_off, lat_val, lon_val, dist in pairs:
    print(f"  lat={lat_val:.6f}  lon={lon_val:.6f}  "
          f"(lat_off={lat_off}, lon_off={lon_off}, dist={dist})")
    # 顯示周圍 32 bytes（找類型 enum）
    ctx_start = max(0, min(lat_off, lon_off) - 16)
    ctx_end = min(len(data), max(lat_off, lon_off) + 24)
    ctx = data[ctx_start:ctx_end]
    print(f"    context hex: {ctx.hex()}")
    # 解析 context 裡的小整數（可能是 type/size enum）
    ints = []
    for j in range(len(ctx) - 3):
        v4 = struct.unpack_from("<I", ctx, j)[0]
        if 1 <= v4 <= 20:
            ints.append((ctx_start + j, v4))
    if ints:
        print(f"    small ints (possible enums): {ints[:10]}")
    print()

print(f"Total pairs found: {len(pairs)}")

# 如果沒有配對，直接印出所有 lon
if not pairs:
    print("\nNo pairs found. All lon candidates:")
    for off, v in lon_offsets[:30]:
        print(f"  offset={off:7d}  lon={v:.6f}")
    print("\nAll lat candidates:")
    for off, v in lat_offsets[:30]:
        print(f"  offset={off:7d}  lat={v:.6f}")

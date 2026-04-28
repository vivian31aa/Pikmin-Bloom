import struct
import re
import sys
import os

path = "niantic_dumps/1777346035338_ichigo-rel_nianticlabs_com_rpc2_315824.bin"
if len(sys.argv) > 1:
    path = sys.argv[1]

with open(path, "rb") as f:
    data = f.read()

print(f"Size: {len(data)} bytes")
print(f"First 32 bytes hex: {data[:32].hex()}")
print()

# 找 ASCII 字串
strings = [m.group().decode() for m in re.finditer(rb"[ -~]{6,}", data)]
print(f"ASCII strings ({len(strings)} total, showing first 60):")
for s in strings[:60]:
    print(f"  {repr(s)}")
print()

# 搜尋關鍵字
keywords = [
    b"mushroom", b"Mushroom", b"Large", b"Giant",
    b"Fire", b"Electric", b"Water", b"Crystal", b"Poison",
    b"fungi", b"kinoko",
]
for kw in keywords:
    idx = 0
    while True:
        idx = data.find(kw, idx)
        if idx < 0:
            break
        ctx = data[max(0, idx-15):idx+50]
        print(f"KEYWORD {kw.decode()!r}: offset={idx}")
        print(f"  context hex: {ctx.hex()}")
        try:
            print(f"  context str: {ctx.decode('utf-8', errors='replace')!r}")
        except Exception:
            pass
        idx += 1

# 座標掃描
print("\nDouble coordinate candidates:")
count = 0
for i in range(0, len(data) - 7, 4):
    v = struct.unpack_from("<d", data, i)[0]
    if 20 <= v <= 26 and count < 30:
        print(f"  lat(TW)? offset={i:7d}  val={v:.6f}")
        count += 1
    elif 119 <= v <= 123 and count < 30:
        print(f"  lon(TW)? offset={i:7d}  val={v:.6f}")
        count += 1

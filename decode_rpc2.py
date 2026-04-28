"""
decode_rpc2.py
--------------
Deep analysis of a Niantic rpc2 binary dump.

Goal: find mushroom type/size near GPS coordinate pairs.

Strategy:
  1. Find all tight lat+lon double pairs (distance = 8 or 16 bytes).
  2. Print the 128-byte record context around each pair.
  3. Scan for repeating record structures (fixed-stride arrays).
  4. Try FlatBuffers vtable parsing from the root offset.
  5. Print entropy map to locate encrypted vs plaintext regions.

Usage:
  python decode_rpc2.py <path_to_bin>
  python decode_rpc2.py niantic_dumps/1777346035338_ichigo-rel_nianticlabs_com_rpc2_315824.bin
"""

import struct
import sys
import math
import os

path = "niantic_dumps/1777346035338_ichigo-rel_nianticlabs_com_rpc2_315824.bin"
if len(sys.argv) > 1:
    path = sys.argv[1]

with open(path, "rb") as f:
    data = f.read()

print(f"File: {path}")
print(f"Size: {len(data)} bytes")
print(f"First 32 bytes: {data[:32].hex()}")
print()

# ── Helper ────────────────────────────────────────────────────────────────────

def read_u32le(data, off):
    return struct.unpack_from("<I", data, off)[0]

def read_i32le(data, off):
    return struct.unpack_from("<i", data, off)[0]

def read_d(data, off):
    return struct.unpack_from("<d", data, off)[0]

def entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    n = len(chunk)
    return -sum((c/n) * math.log2(c/n) for c in freq if c)

def hexdump(data, offset, length=128, mark_offsets=None):
    mark_offsets = set(mark_offsets or [])
    end = min(offset + length, len(data))
    for row in range(offset, end, 16):
        raw = data[row:row+16]
        hex_part = " ".join(
            f"\033[1;33m{b:02x}\033[0m" if (row + j) in mark_offsets else f"{b:02x}"
            for j, b in enumerate(raw)
        )
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        print(f"  {row:08x}  {hex_part:<47}  {asc}")


# ── 1. Entropy map (256-byte blocks) ─────────────────────────────────────────

print("=== Entropy map (256-byte blocks, H=entropy 0-8) ===")
block = 256
cols = 8
for i in range(0, len(data), block * cols):
    row_parts = []
    for j in range(cols):
        off = i + j * block
        if off >= len(data):
            break
        chunk = data[off:off+block]
        h = entropy(chunk)
        bar = "▓" if h > 7.5 else ("▒" if h > 6.5 else ("░" if h > 5.0 else " "))
        row_parts.append(f"{off:7d}:{h:.1f}{bar}")
    print("  " + "  ".join(row_parts))
print()

# ── 2. Tight double-double pairs ──────────────────────────────────────────────

print("=== Tight lat+lon double pairs (distance 8 or 16 bytes) ===")
print("  Looking for IEEE 754 doubles: lat ∈ [20,27], lon ∈ [118,125]")
print()

lat_offs = []
lon_offs = []
for i in range(0, len(data) - 7):
    v = read_d(data, i)
    if 20.0 <= v <= 27.0:
        lat_offs.append((i, v))
    elif 118.0 <= v <= 125.0:
        lon_offs.append((i, v))

# Index lons by offset for fast lookup
lon_by_off = {o: v for o, v in lon_offs}

tight_pairs = []
for lo, lv in lat_offs:
    for delta in (8, 16, -8, -16):
        no = lo + delta
        if no in lon_by_off:
            tight_pairs.append((lo, no, lv, lon_by_off[no], delta))

print(f"Found {len(lat_offs)} lat candidates, {len(lon_offs)} lon candidates")
print(f"Tight pairs (Δ=±8 or ±16): {len(tight_pairs)}")
print()

for lo, no, lv, nv, delta in tight_pairs:
    base = min(lo, no) - 32
    base = max(0, base)
    ctx_start = base
    ctx_end   = min(len(data), max(lo, no) + 40)
    print(f"  lat={lv:.6f} @ {lo:#010x}  lon={nv:.6f} @ {no:#010x}  Δ={delta:+d}")
    # entropy of surrounding 64 bytes
    surr = data[max(0,lo-32):no+40]
    print(f"  entropy of ±32 context: {entropy(surr):.2f}")
    hexdump(data, ctx_start, ctx_end - ctx_start, mark_offsets=[lo, lo+1, lo+2, lo+3,
                                                                   lo+4, lo+5, lo+6, lo+7,
                                                                   no, no+1, no+2, no+3,
                                                                   no+4, no+5, no+6, no+7])
    # also try to read 4 bytes just before lat as possible field tag or size
    if lo >= 4:
        pre4 = data[lo-4:lo]
        pre_u32 = struct.unpack_from("<I", pre4)[0]
        pre_i32 = struct.unpack_from("<i", pre4)[0]
        print(f"  4 bytes before lat: {pre4.hex()}  u32={pre_u32}  i32={pre_i32}")
    print()

# ── 3. Stride analysis ────────────────────────────────────────────────────────
# If mushroom records are a fixed-size array, consecutive lat pairs will be
# evenly spaced.

print("=== Stride analysis between consecutive tight lat pairs ===")
if len(tight_pairs) >= 2:
    sorted_pairs = sorted(tight_pairs, key=lambda x: x[0])
    strides = []
    for i in range(1, len(sorted_pairs)):
        s = sorted_pairs[i][0] - sorted_pairs[i-1][0]
        strides.append(s)
    from collections import Counter
    cnt = Counter(strides)
    print("  Top strides (bytes between consecutive lat offsets):")
    for stride, freq in cnt.most_common(10):
        print(f"    stride={stride}  count={freq}")
else:
    print("  (not enough pairs)")
print()

# ── 4. FlatBuffers root parsing ───────────────────────────────────────────────

print("=== FlatBuffers root object attempt ===")
# FlatBuffers root: first 4 bytes = offset to root table
if len(data) >= 4:
    root_off = read_u32le(data, 0)
    print(f"  Root offset (first u32le): {root_off}  → table at byte {root_off}")
    if root_off < len(data) - 4:
        vtable_soff = read_i32le(data, root_off)  # signed offset to vtable
        vtable_off  = root_off - vtable_soff       # vtable is BEFORE the table
        print(f"  vtable soffset: {vtable_soff}  → vtable at {vtable_off}")
        if 0 <= vtable_off < len(data) - 4:
            vt_size  = read_u32le(data, vtable_off) & 0xFFFF
            obj_size = (read_u32le(data, vtable_off) >> 16) & 0xFFFF
            print(f"  vtable size={vt_size}, object inline size={obj_size}")
            print(f"  vtable raw: {data[vtable_off:vtable_off+min(vt_size,64)].hex()}")
            # field offsets within vtable (2 bytes each, starting at vtable_off+4)
            fields = []
            for f in range((vt_size - 4) // 2):
                field_off = struct.unpack_from("<H", data, vtable_off + 4 + f*2)[0]
                fields.append(field_off)
            print(f"  Field offsets (relative to object start): {fields[:20]}")
print()

# ── 5. Search for int32*1e7 tight pairs ───────────────────────────────────────

print("=== Tight int32*1e7 lat+lon pairs ===")
ilat_offs = []
ilon_offs = []
for i in range(0, len(data) - 3):
    v = read_i32le(data, i)
    if 200_000_000 <= v <= 270_000_000:
        ilat_offs.append((i, v / 1e7))
    elif 1_180_000_000 <= v <= 1_250_000_000:
        ilon_offs.append((i, v / 1e7))

ilon_by_off = {o: v for o, v in ilon_offs}

itight = []
for lo, lv in ilat_offs:
    for delta in (4, 8, -4, -8):
        no = lo + delta
        if no in ilon_by_off:
            itight.append((lo, no, lv, ilon_by_off[no], delta))

print(f"Found {len(ilat_offs)} int-lat candidates, {len(ilon_offs)} int-lon candidates")
print(f"Tight int pairs (Δ=±4 or ±8): {len(itight)}")
print()

for lo, no, lv, nv, delta in itight[:20]:
    base = max(0, min(lo, no) - 32)
    ctx_end = min(len(data), max(lo, no) + 16)
    print(f"  lat={lv:.6f} @ {lo:#010x}  lon={nv:.6f} @ {no:#010x}  Δ={delta:+d}")
    hexdump(data, base, ctx_end - base, mark_offsets=[lo, lo+1, lo+2, lo+3, no, no+1, no+2, no+3])
    print()

# ── 6. Protobuf wire scan around coordinate pairs ─────────────────────────────

print("=== Protobuf wire-type scan near first 5 tight double pairs ===")
def read_varint(data, pos):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos

def proto_scan(data, start, length=256):
    """Scan a region for plausible protobuf tags."""
    end = min(start + length, len(data))
    pos = start
    fields = []
    while pos < end:
        try:
            tag, npos = read_varint(data, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 0x7
        if field_num == 0 or field_num > 500 or wire_type > 5:
            pos += 1
            continue
        if wire_type == 0:
            val, npos = read_varint(data, npos)
            fields.append((pos, f"F{field_num}:varint={val}"))
            pos = npos
        elif wire_type == 1:
            if npos + 8 > len(data): break
            val = struct.unpack_from("<d", data, npos)[0]
            fields.append((pos, f"F{field_num}:double={val:.6f}"))
            pos = npos + 8
        elif wire_type == 5:
            if npos + 4 > len(data): break
            val = struct.unpack_from("<f", data, npos)[0]
            fields.append((pos, f"F{field_num}:float={val:.6f}"))
            pos = npos + 4
        elif wire_type == 2:
            try:
                length2, npos2 = read_varint(data, npos)
                if npos2 + length2 > len(data) or length2 > 100_000:
                    pos += 1
                    continue
                fields.append((pos, f"F{field_num}:bytes(len={length2})"))
                pos = npos2 + length2
            except Exception:
                pos += 1
        else:
            pos += 1
        if len(fields) > 20:
            break
    return fields

for lo, no, lv, nv, delta in tight_pairs[:5]:
    scan_start = max(0, min(lo, no) - 64)
    print(f"  Proto scan @ lat={lv:.5f} region [{scan_start:#x} +256]:")
    for off, desc in proto_scan(data, scan_start, 256):
        print(f"    {off:#010x}  {desc}")
    print()

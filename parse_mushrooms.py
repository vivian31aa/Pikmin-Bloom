"""
parse_mushrooms.py
------------------
從 pre_free dump 裡解析蘑菇座標、類型和大小。

用法：
  python parse_mushrooms.py <dump_file.bin>
  python parse_mushrooms.py decrypted_dumps/068_pre_free*.bin
  python parse_mushrooms.py --all decrypted_dumps/   # 掃所有檔案

輸出模式：
  (預設)     每個座標 + ctx hex
  --csv      CSV: lat,lon,file,offset,enc,ctx[,fields]
  --json     JSON 陣列
  --fields   在 ctx 裡掃 type/size/timestamp 候選欄位
  --inspect  印出每個座標周圍的完整 hexdump
  --stride   計算相鄰座標間距（推算 record 大小）
"""

import struct
import sys
import os
import math
import glob
import argparse
import json
from collections import Counter


# Taiwan + 周邊區域範圍
LAT_MIN, LAT_MAX = 20.0, 27.0
LON_MIN, LON_MAX = 118.0, 125.5

CTX_RADIUS = 64   # bytes before/after coord to capture


# ---------------------------------------------------------------------------
# Coordinate scanners
# ---------------------------------------------------------------------------

def scan_doubles(data: bytes):
    """掃描所有台灣 lat/lon double pairs，返回 (lat_off, lon_off, lat, lon, delta)。"""
    results = []
    n = len(data)
    for i in range(0, n - 15, 1):  # step=1: protobuf doubles are not 4-byte aligned
        try:
            lat = struct.unpack_from('<d', data, i)[0]
        except Exception:
            continue
        if not math.isfinite(lat) or not (LAT_MIN <= lat <= LAT_MAX):
            continue
        for delta in (8, 16, -8, -16, 24, -24):
            j = i + delta
            if j < 0 or j + 8 > n:
                continue
            try:
                lon = struct.unpack_from('<d', data, j)[0]
            except Exception:
                continue
            if math.isfinite(lon) and LON_MIN <= lon <= LON_MAX:
                results.append((i, j, lat, lon, delta))
                break
    return results


def scan_int7(data: bytes):
    """掃描 int32*1e7 編碼的台灣座標對。"""
    results = []
    n = len(data)
    for i in range(0, n - 7, 1):  # step=1 for unaligned protobuf fields
        try:
            v = struct.unpack_from('<i', data, i)[0]
        except Exception:
            continue
        if not (200_000_000 <= v <= 270_000_000):
            continue
        lat = v / 1e7
        for delta in (4, 8, -4, -8):
            j = i + delta
            if j < 0 or j + 4 > n:
                continue
            try:
                w = struct.unpack_from('<i', data, j)[0]
            except Exception:
                continue
            if 1_180_000_000 <= w <= 1_255_000_000:
                results.append((i, j, lat, w / 1e7, delta))
                break
    return results


# ---------------------------------------------------------------------------
# Context / field helpers
# ---------------------------------------------------------------------------

def read_context(data: bytes, off: int, radius: int = CTX_RADIUS) -> bytes:
    start = max(0, off - radius)
    end   = min(len(data), off + radius + 8)
    return data[start:end]


def hexdump(data: bytes, start_addr: int = 0) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        addr  = start_addr + i
        hex_s = ' '.join(f'{b:02x}' for b in chunk)
        asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {addr:08x}  {hex_s:<47}  {asc_s}')
    return '\n'.join(lines)


def scan_fields(data: bytes, lat_off: int, lon_off: int, enc: str) -> dict:
    """
    在座標附近掃描候選欄位：
      small_uint / small_int  → type / size / HP (1–200)
      timestamp_ms            → unix 毫秒時間戳
      timestamp_s             → unix 秒時間戳
      id_u64                  → S2 cell ID 或 mushroom UUID (>2^40)

    回傳 {相對偏移: (欄位類型, 值)} dict（相對於 lat_off）。
    """
    if enc == 'double':
        coord_end = max(lat_off, lon_off) + 8
    else:
        coord_end = max(lat_off, lon_off) + 4

    candidates = {}
    n = len(data)
    search_start = max(0, min(lat_off, lon_off) - 64)
    search_end   = min(n, coord_end + 64)

    for j in range(search_start, search_end - 3, 4):
        # 跳過座標本身占用的 bytes
        if enc == 'double':
            if lat_off <= j < lat_off + 8 or lon_off <= j < lon_off + 8:
                continue
        else:
            if lat_off <= j < lat_off + 4 or lon_off <= j < lon_off + 4:
                continue

        rel   = j - lat_off
        v32u  = struct.unpack_from('<I', data, j)[0]
        v32s  = struct.unpack_from('<i', data, j)[0]

        if 1 <= v32u <= 200:
            candidates[rel] = ('small_uint', v32u)
            continue
        if 1 <= v32s <= 200:
            candidates[rel] = ('small_int',  v32s)
            continue

        if j + 8 <= n:
            v64 = struct.unpack_from('<Q', data, j)[0]
            if 1_600_000_000_000 <= v64 <= 2_100_000_000_000:
                candidates[rel] = ('timestamp_ms', v64)
            elif 1_600_000_000 <= v64 <= 2_100_000_000:
                candidates[rel] = ('timestamp_s',  v64)
            elif v64 > (1 << 40):
                candidates[rel] = ('id_u64', hex(v64))

    return candidates


def _field_summary(fields: dict) -> str:
    parts = []
    for rel, (ftype, val) in sorted(fields.items()):
        parts.append(f'{rel:+d}:{ftype}={val}')
    return '|'.join(parts)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate(pairs, min_delta_deg: float = 0.0001):
    """合併非常接近的重複座標（同一蘑菇被掃到多次）。"""
    seen = []
    for p in sorted(pairs, key=lambda x: (x[2], x[3])):
        lat, lon = p[2], p[3]
        dup = any(abs(lat - s[2]) < min_delta_deg and abs(lon - s[3]) < min_delta_deg
                  for s in seen)
        if not dup:
            seen.append(p)
    return seen


# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------

def analyse_file(path: str):
    data  = open(path, 'rb').read()
    fname = os.path.basename(path)

    d_uniq = deduplicate(scan_doubles(data))
    i_uniq = deduplicate(scan_int7(data))

    all_pairs = []
    for lat_off, lon_off, lat, lon, delta in d_uniq:
        ctx = read_context(data, lat_off)
        all_pairs.append({
            'lat': lat, 'lon': lon,
            'enc': 'double',
            'lat_off': lat_off,
            'lon_off': lon_off,
            'ctx': ctx.hex(),
            'ctx_bytes': ctx,
            'ctx_base': max(0, lat_off - CTX_RADIUS),
            'fields': scan_fields(data, lat_off, lon_off, 'double'),
        })

    for lat_off, lon_off, lat, lon, delta in i_uniq:
        dup = any(abs(lat - p['lat']) < 0.001 and abs(lon - p['lon']) < 0.001
                  for p in all_pairs)
        if not dup:
            ctx = read_context(data, lat_off)
            all_pairs.append({
                'lat': lat, 'lon': lon,
                'enc': 'int7',
                'lat_off': lat_off,
                'lon_off': lon_off,
                'ctx': ctx.hex(),
                'ctx_bytes': ctx,
                'ctx_base': max(0, lat_off - CTX_RADIUS),
                'fields': scan_fields(data, lat_off, lon_off, 'int7'),
            })

    return fname, data, all_pairs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='*')
    parser.add_argument('--all',     metavar='DIR', help='Scan all .bin in DIR')
    parser.add_argument('--csv',     action='store_true', help='CSV output (includes ctx)')
    parser.add_argument('--json',    action='store_true', help='JSON output')
    parser.add_argument('--fields',  action='store_true',
                        help='掃 type/size/timestamp 候選欄位')
    parser.add_argument('--inspect', action='store_true',
                        help='印出每個座標周圍 hexdump')
    parser.add_argument('--stride',  action='store_true',
                        help='計算相鄰座標間距（推算 record 大小）')
    args = parser.parse_args()

    paths = list(args.files)
    if args.all:
        paths += sorted(glob.glob(os.path.join(args.all, '*.bin')))
    if not paths:
        parser.print_help()
        sys.exit(1)

    all_mushrooms = []

    for path in paths:
        if not os.path.exists(path):
            print(f'[skip] {path} not found', file=sys.stderr)
            continue
        fname, data, pairs = analyse_file(path)
        print(f'\n=== {fname}  size={len(data):,}  coords={len(pairs)} ===',
              file=sys.stderr)

        for p in pairs:
            p['file'] = fname
            all_mushrooms.append(p)

            if not args.csv and not args.json:
                print(f"  lat={p['lat']:.6f}  lon={p['lon']:.6f}"
                      f"  @{p['lat_off']:#010x}  enc={p['enc']}")
                if args.fields:
                    if p['fields']:
                        for rel, (ftype, val) in sorted(p['fields'].items()):
                            print(f"    [{rel:+4d}]  {ftype:<14}  {val}")
                    else:
                        print("    (no candidates)")
                else:
                    print(f"  ctx: {p['ctx']}")

            if args.inspect:
                base = p['ctx_base']
                print(f"\n  --- hexdump @ {base:#x} (lat_off={p['lat_off']:#x}) ---")
                print(hexdump(p['ctx_bytes'], start_addr=base))

    # JSON output
    if args.json:
        out = []
        for m in all_mushrooms:
            rec = {k: v for k, v in m.items() if k != 'ctx_bytes'}
            if not args.fields:
                rec.pop('fields', None)
            else:
                rec['fields'] = {str(k): list(v) for k, v in m['fields'].items()}
            out.append(rec)
        print(json.dumps(out, indent=2))

    # CSV output
    if args.csv:
        header = 'lat,lon,file,offset,enc,ctx'
        if args.fields:
            header += ',fields'
        print(header)
        for m in all_mushrooms:
            row = (f"{m['lat']:.7f},{m['lon']:.7f},{m['file']},"
                   f"{m['lat_off']:#x},{m['enc']},{m['ctx']}")
            if args.fields:
                row += ',' + _field_summary(m['fields'])
            print(row)

    # Stride analysis
    if args.stride and all_mushrooms:
        first_file = all_mushrooms[0]['file']
        offsets = sorted(set(m['lat_off'] for m in all_mushrooms
                             if m['file'] == first_file))
        if len(offsets) >= 2:
            strides = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
            cnt = Counter(strides)
            print('\nStride analysis:', file=sys.stderr)
            for s, c in cnt.most_common(5):
                print(f'  stride={s} bytes/record  count={c}', file=sys.stderr)

    # Field frequency across all mushrooms
    if args.fields and all_mushrooms:
        print('\n--- Field offset frequency (small_int candidates) ---', file=sys.stderr)
        off_count:  Counter = Counter()
        off_values: dict    = {}
        for m in all_mushrooms:
            for rel, (ftype, val) in m['fields'].items():
                if 'int' in ftype:
                    off_count[rel] += 1
                    off_values.setdefault(rel, Counter())[val] += 1
        for rel, cnt in off_count.most_common(20):
            val_dist = off_values[rel].most_common(5)
            print(f'  rel={rel:+4d}  count={cnt:3d}  values={val_dist}',
                  file=sys.stderr)

    print(f'\nTotal unique mushrooms: {len(all_mushrooms)}', file=sys.stderr)


if __name__ == '__main__':
    main()

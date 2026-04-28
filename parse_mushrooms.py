"""
parse_mushrooms.py
------------------
從 pre_free dump 裡解析蘑菇座標、類型和大小。

用法：
  python parse_mushrooms.py <dump_file.bin>
  python parse_mushrooms.py decrypted_dumps/068_pre_free*.bin
  python parse_mushrooms.py --all decrypted_dumps/   # 掃所有檔案

輸出：CSV to stdout，格式：
  lat, lon, file, offset, context_hex
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


def scan_doubles(data: bytes):
    """掃描所有台灣 lat/lon double pairs，返回 (lat_off, lon_off, lat, lon, delta)。"""
    results = []
    dv = memoryview(data).cast('B')
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


def read_context(data: bytes, off: int, radius: int = 48) -> bytes:
    start = max(0, off - radius)
    end = min(len(data), off + radius + 8)
    return data[start:end]


def hexdump_line(chunk: bytes, highlight_off: int = None) -> str:
    return ' '.join(f'{b:02x}' for b in chunk)


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


def analyse_file(path: str, verbose: bool = False):
    data = open(path, 'rb').read()
    fname = os.path.basename(path)

    d_pairs = scan_doubles(data)
    i_pairs = scan_int7(data)

    # Deduplicate each set
    d_uniq = deduplicate(d_pairs)
    i_uniq = deduplicate(i_pairs)

    # Combine and deduplicate across both
    all_pairs = []
    for lat_off, lon_off, lat, lon, delta in d_uniq:
        all_pairs.append({
            'lat': lat, 'lon': lon,
            'enc': 'double',
            'lat_off': lat_off,
            'ctx': read_context(data, lat_off, 32).hex(),
        })
    for lat_off, lon_off, lat, lon, delta in i_uniq:
        # Skip if already covered by a nearby double
        dup = any(abs(lat - p['lat']) < 0.001 and abs(lon - p['lon']) < 0.001
                  for p in all_pairs)
        if not dup:
            all_pairs.append({
                'lat': lat, 'lon': lon,
                'enc': 'int7',
                'lat_off': lat_off,
                'ctx': read_context(data, lat_off, 32).hex(),
            })

    return fname, data, all_pairs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='*')
    parser.add_argument('--all', metavar='DIR', help='Scan all .bin in DIR')
    parser.add_argument('--csv', action='store_true', help='CSV output')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--stride', action='store_true',
                        help='Compute stride between consecutive coordinates')
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
                print(f"  ctx: {p['ctx']}")

    if args.json:
        print(json.dumps([{k: v for k, v in m.items() if k != 'ctx'}
                          for m in all_mushrooms], indent=2))

    if args.csv:
        print('lat,lon,file,offset,enc')
        for m in all_mushrooms:
            print(f"{m['lat']:.7f},{m['lon']:.7f},{m['file']},{m['lat_off']:#x},{m['enc']}")

    # Stride analysis (detect record size)
    if args.stride and all_mushrooms:
        offsets = sorted(set(m['lat_off'] for m in all_mushrooms
                             if m.get('file') == all_mushrooms[0]['file']))
        if len(offsets) >= 2:
            strides = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
            cnt = Counter(strides)
            print('\nStride analysis:', file=sys.stderr)
            for s, c in cnt.most_common(5):
                print(f'  stride={s} ({s} bytes / record)  count={c}', file=sys.stderr)

    print(f'\nTotal unique mushrooms across all files: {len(all_mushrooms)}',
          file=sys.stderr)


if __name__ == '__main__':
    main()

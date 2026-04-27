"""
analyze_dumps.py
-----------------
從 mitmdump -w 儲存的 .mitm 捕獲檔（或 niantic_dumps/*.bin）中
解析 Niantic rpc2 回應，尋找菇的資料。

用法：
  # 從 mitmdump -w 捕獲的 flow 檔
  python analyze_dumps.py --flow capture.mitm

  # 從 niantic_dumps/ 目錄裡的 .bin 檔
  python analyze_dumps.py --bindir niantic_dumps

  # 同時搜尋、顯示原始 hex
  python analyze_dumps.py --flow capture.mitm --hex

安裝：
  pip install mitmproxy blackboxprotobuf
"""

import sys
import os
import re
import struct
import argparse
import json


# ---------------------------------------------------------------------------
# Protobuf 解析嘗試
# ---------------------------------------------------------------------------

def try_blackbox(data: bytes, max_depth=6, _depth=0) -> dict | None:
    try:
        import blackboxprotobuf
        msg, _ = blackboxprotobuf.decode_message(data)
        return msg
    except Exception:
        return None


def search_floats(data: bytes):
    """找出 data 裡所有可能是 lat/lon 的 4-byte float。"""
    results = []
    for i in range(0, len(data) - 3, 1):
        val = struct.unpack_from("<f", data, i)[0]
        if -90 <= val <= 90 and abs(val) > 0.001:
            results.append(("float_lat?", i, val))
        elif -180 <= val <= 180 and abs(val) > 0.001:
            results.append(("float_lon?", i, val))
    return results


def search_doubles(data: bytes):
    """找出 data 裡所有可能是 lat/lon 的 8-byte double。"""
    results = []
    for i in range(0, len(data) - 7, 1):
        val = struct.unpack_from("<d", data, i)[0]
        if -90 <= val <= 90 and abs(val) > 0.01:
            results.append(("double_lat?", i, val))
        elif -180 <= val <= 180 and abs(val) > 0.01:
            results.append(("double_lon?", i, val))
    return results


MUSHROOM_KEYWORDS = [
    b"mushroom", b"Mushroom", b"MUSHROOM",
    b"Large", b"Giant", b"Small",
    b"Fire", b"Electric", b"Water", b"Crystal", b"Poison",
    b"Red", b"Yellow", b"Blue", b"Purple", b"White",
    b"fungi", b"Fungi",
]


def search_strings(data: bytes):
    """找出 data 裡的已知關鍵字。"""
    results = []
    for kw in MUSHROOM_KEYWORDS:
        pos = 0
        while True:
            idx = data.find(kw, pos)
            if idx < 0:
                break
            context = data[max(0, idx-20):idx+80]
            results.append((idx, kw.decode("utf-8", errors="replace"),
                            context.decode("utf-8", errors="replace")))
            pos = idx + 1
    return results


def find_all_ascii(data: bytes, min_len=6):
    """提取所有長度 >= min_len 的可印出 ASCII 字串。"""
    pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
    return [m.group().decode() for m in re.finditer(pattern, data)]


# ---------------------------------------------------------------------------
# 解析 varint（protobuf 基礎）
# ---------------------------------------------------------------------------

def read_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


def manual_proto_fields(data: bytes):
    """簡單手動掃描 protobuf，輸出 field_id 和前幾個 bytes。"""
    fields = []
    pos = 0
    while pos < len(data):
        try:
            tag, pos = read_varint(data, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 0x7
        if field_num == 0 or field_num > 10000:
            break
        if wire_type == 0:  # varint
            val, pos = read_varint(data, pos)
            fields.append({"field": field_num, "type": "varint", "value": val})
        elif wire_type == 2:  # length-delimited
            length, pos = read_varint(data, pos)
            if pos + length > len(data) or length > 10_000_000:
                break
            content = data[pos:pos+length]
            fields.append({"field": field_num, "type": "bytes",
                           "length": length,
                           "preview": content[:60].hex()})
            pos += length
        elif wire_type == 1:  # 64-bit
            val = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            fields.append({"field": field_num, "type": "64bit", "value": val})
        elif wire_type == 5:  # 32-bit
            val = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            fields.append({"field": field_num, "type": "32bit", "value": val})
        else:
            break
    return fields


# ---------------------------------------------------------------------------
# 分析單一 body
# ---------------------------------------------------------------------------

def analyze_body(data: bytes, label: str, show_hex: bool = False):
    print(f"\n{'='*60}")
    print(f"  {label}  ({len(data)} bytes)")
    print(f"{'='*60}")

    if show_hex:
        print(f"[HEX first 128]: {data[:128].hex()}")

    # 1. 搜尋字串關鍵字
    hits = search_strings(data)
    if hits:
        print(f"\n[Keywords found: {len(hits)}]")
        for idx, kw, ctx in hits:
            print(f"  offset {idx:6d}  kw={kw!r:15s}  ...{ctx!r}...")

    # 2. 所有 ASCII 字串
    strings = find_all_ascii(data, min_len=8)
    if strings:
        print(f"\n[ASCII strings (len>=8): {len(strings)}]")
        for s in strings[:40]:
            print(f"  {s!r}")
        if len(strings) > 40:
            print(f"  ... ({len(strings)-40} more)")

    # 3. blackboxprotobuf 解析
    msg = try_blackbox(data)
    if msg:
        print(f"\n[Protobuf (blackbox)]: {len(msg)} top-level fields")
        txt = json.dumps(msg, default=lambda x: x.hex() if isinstance(x, bytes) else str(x), indent=2)
        # 截斷超長輸出
        if len(txt) > 3000:
            txt = txt[:3000] + "\n  ... (truncated)"
        print(txt)
    else:
        # 4. 手動掃描 protobuf fields
        fields = manual_proto_fields(data)
        if fields:
            print(f"\n[Manual proto scan]: {len(fields)} fields")
            for f in fields[:30]:
                print(f"  {f}")

    # 5. double 座標掃描
    dbl = search_doubles(data)
    if dbl:
        # 把 lat/lon 配對
        print(f"\n[Coordinate doubles ({len(dbl)} candidates)]")
        lats = [(i, v) for t, i, v in dbl if t == "double_lat?"]
        lons = [(i, v) for t, i, v in dbl if t == "double_lon?"]
        for off, v in lats[:20]:
            print(f"  lat? offset={off:6d}  val={v:.6f}")
        for off, v in lons[:20]:
            print(f"  lon? offset={off:6d}  val={v:.6f}")


# ---------------------------------------------------------------------------
# 從 .bin 目錄分析
# ---------------------------------------------------------------------------

def analyze_bindir(bindir: str, show_hex: bool):
    files = sorted(f for f in os.listdir(bindir) if f.endswith(".bin"))
    if not files:
        print(f"[Error] {bindir} 裡沒有 .bin 檔")
        return

    print(f"找到 {len(files)} 個 .bin 檔")

    # 優先分析 rpc2 相關的（檔名包含 niantic）
    rpc2_files = [f for f in files if "ichigo" in f or "rpc" in f]
    other_files = [f for f in files if f not in rpc2_files]

    print(f"  rpc2/ichigo: {len(rpc2_files)} 個")
    print(f"  其他: {len(other_files)} 個")

    for fname in (rpc2_files or files)[:20]:
        path = os.path.join(bindir, fname)
        with open(path, "rb") as f:
            data = f.read()
        analyze_body(data, fname, show_hex)


# ---------------------------------------------------------------------------
# 從 mitmdump flow 檔分析
# ---------------------------------------------------------------------------

def analyze_flow(flow_path: str, show_hex: bool):
    try:
        from mitmproxy.io import FlowReader
        from mitmproxy.net.http import http1
    except ImportError:
        print("[Error] 需要安裝 mitmproxy: pip install mitmproxy")
        sys.exit(1)

    niantic_hosts = ["nianticlabs.com", "niantic.net", "pikmin-bloom.com"]
    count = 0

    with open(flow_path, "rb") as fp:
        reader = FlowReader(fp)
        for flow in reader.stream():
            host = flow.request.pretty_host
            if not any(h in host for h in niantic_hosts):
                continue

            url = flow.request.pretty_url
            body = flow.response.get_content() if flow.response else b""
            if not body:
                continue

            count += 1
            label = f"[{count}] {flow.request.method} {url}"
            analyze_body(body, label, show_hex)

    if count == 0:
        print("[Info] 沒有找到 Niantic 的 response，請確認 flow 檔是否正確")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="分析 Niantic API dump，尋找菇的資料")
    p.add_argument("--flow",   default=None, help="mitmdump -w 儲存的 .mitm flow 檔")
    p.add_argument("--bindir", default="niantic_dumps",
                   help="niantic_dumps/ 目錄（proxy_sniffer.py 的 dump 輸出）")
    p.add_argument("--hex",    action="store_true", help="顯示前 128 bytes hex")
    args = p.parse_args()

    if args.flow:
        analyze_flow(args.flow, args.hex)
    else:
        if not os.path.isdir(args.bindir):
            print(f"[Error] 找不到目錄 {args.bindir}，請用 --flow 或 --bindir 指定")
            sys.exit(1)
        analyze_bindir(args.bindir, args.hex)


if __name__ == "__main__":
    main()

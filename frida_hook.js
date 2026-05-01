/**
 * frida_hook.js
 * Capture Pikmin Bloom rpc2 response (encrypted) and decrypted payload.
 * Confirmed: game uses java.net.URL → native TLS → libNianticLabsPlugin.so decrypt
 */

"use strict";

const MIN_DUMP_SIZE = 50000;
let dumpIndex = 0;

// malloc/free tracker — armed after large SSL_read to catch decrypted buffer
let trackMalloc = false;
let trackSmall  = false;  // arm to catch small buffers (1000-50000 bytes)
const capturedAddrs = new Set();  // deduplicate: only dump each addr once per session
const largeAllocs = new Map();  // ptr_str → size
const smallAllocs = new Map();  // ptr_str → size (1000-50000 byte range)

// ---------------------------------------------------------------------------
// ART/Dalvik heap range exclusion — read once, used by all coord scanners
// ---------------------------------------------------------------------------
let _artRanges = null;  // [{base: ptr, end: ptr}]

function getArtRanges() {
    if (_artRanges) return _artRanges;
    _artRanges = [];
    try {
        const fopen  = new NativeFunction(Module.findExportByName("libc.so", "fopen"),  'pointer', ['pointer', 'pointer']);
        const fgets  = new NativeFunction(Module.findExportByName("libc.so", "fgets"),  'pointer', ['pointer', 'int', 'pointer']);
        const fclose = new NativeFunction(Module.findExportByName("libc.so", "fclose"), 'int',     ['pointer']);
        const f = fopen(Memory.allocUtf8String("/proc/self/maps"), Memory.allocUtf8String("r"));
        if (!f.isNull()) {
            const buf = Memory.alloc(512);
            while (true) {
                if (fgets(buf, 512, f).isNull()) break;
                const line = buf.readUtf8String();
                if (!line.includes("dalvik") && !line.includes(".art") &&
                    !line.includes("jit-code-cache") && !line.includes("indirect ref")) continue;
                const m = line.match(/^([0-9a-f]+)-([0-9a-f]+)/);
                if (m) _artRanges.push({ base: ptr("0x" + m[1]), end: ptr("0x" + m[2]) });
            }
            fclose(f);
        }
    } catch(e) { console.log("[-] getArtRanges: " + e); }
    console.log("[*] ART exclusion ranges loaded: " + _artRanges.length);
    return _artRanges;
}

function isArtAddress(p) {
    const artRanges = getArtRanges();
    for (const r of artRanges) {
        if (p.compare(r.base) >= 0 && p.compare(r.end) < 0) return true;
    }
    return false;
}

// ASCII density of a context window: fraction of bytes in printable ASCII range
function asciiDensity(arr, off, len) {
    len = Math.min(len, arr.length - off);
    if (len <= 0) return 0;
    let cnt = 0;
    for (let i = off; i < off + len; i++) {
        const b = arr[i];
        if (b >= 0x20 && b < 0x7f) cnt++;
    }
    return cnt / len;
}

function hexOf(arr, n) {
    n = Math.min(n || 32, arr.length);
    let s = "";
    for (let i = 0; i < n; i++) s += ("0" + (arr[i] & 0xff).toString(16)).slice(-2) + " ";
    return s.trimEnd();
}

// sendBufRaw: no min-size gate — for small mushroom record buffers
function sendBufRaw(label, alg, bytes) {
    if (!bytes || bytes.length === 0) return;
    const idx = dumpIndex++;
    console.log("\n[CAPTURED] " + label + "  len=" + bytes.length);
    console.log("  preview: " + hexOf(bytes, 32));
    send({ type:"buffer", index:idx, label:label, alg:alg, len:bytes.length },
         bytes.buffer || bytes);
}

function sendBuf(label, alg, bytes) {
    if (!bytes || bytes.length < MIN_DUMP_SIZE) return;
    const idx = dumpIndex++;
    console.log("\n[CAPTURED] " + label + "  len=" + bytes.length);
    console.log("  preview: " + hexOf(bytes, 32));
    if (bytes.length >= 4) {
        const u32 = bytes[0]|(bytes[1]<<8)|(bytes[2]<<16)|(bytes[3]<<24);
        if (u32 > 0 && u32 < 500) console.log("  ** FlatBuffers root_off=" + u32);
    }
    send({ type:"buffer", index:idx, label:label, alg:alg, len:bytes.length },
         bytes.buffer || bytes);
}

// ── 1. SSL_read — fixed: save buf pointer in onEnter ─────────────────────────
let rpc2LargeDetected = false;  // flag to trigger auto memory scan

(function() {
    const fn = Module.findExportByName("libssl.so", "SSL_read");
    if (!fn) { console.log("[-] SSL_read not found"); return; }

    // Accumulate chunks per SSL* context
    const sslBufs = new Map();   // ssl_ptr_str → {chunks, totalLen}

    Interceptor.attach(fn, {
        onEnter(args) {
            this.ssl = args[0].toString();
            this.buf = args[1];          // save buffer pointer here
            this.num = args[2].toInt32();
        },
        onLeave(retval) {
            const n = retval.toInt32();
            if (n <= 0) return;

            let chunk;
            try { chunk = new Uint8Array(this.buf.readByteArray(n)); }
            catch(_) { return; }

            // Log first read per SSL context
            if (!sslBufs.has(this.ssl)) {
                sslBufs.set(this.ssl, { chunks: [], totalLen: 0 });
                console.log("[SSL_read] new ctx ssl=" + this.ssl.slice(-6) +
                            "  first_n=" + n + "  preview: " + hexOf(chunk, 32));
            }

            const acc = sslBufs.get(this.ssl);
            acc.chunks.push(chunk);
            acc.totalLen += n;

            // When we have >= MIN_DUMP_SIZE, emit the whole thing
            if (acc.totalLen >= MIN_DUMP_SIZE) {
                const full = new Uint8Array(acc.totalLen);
                let off = 0;
                for (const c of acc.chunks) { full.set(c, off); off += c.length; }
                sslBufs.delete(this.ssl);
                sendBuf("SSL_read(ssl=..." + this.ssl.slice(-6) + ")", "tls-raw", full);

                // When large rpc2 chunk arrives: arm malloc tracker + schedule coord scan
                if (full.length > 40000 && !rpc2LargeDetected) {
                    rpc2LargeDetected = true;
                    trackMalloc = true;
                    trackSmall  = true;
                    console.log("[SSL_read] large rpc2 chunk (" + full.length + " bytes) — malloc/small tracker armed for 5s");
                    setTimeout(function() {
                        trackMalloc = false;
                        trackSmall  = false;
                        rpc2LargeDetected = false;
                        console.log("[SSL_read] tracker disarmed — run scan_mushroom_objects() manually");
                    }, 5000);
                }
            }
        }
    });
    console.log("[+] SSL_read hooked (accumulating per SSL context)");
})();

// ── 2. EVP_Decrypt* in all libcrypto.so ──────────────────────────────────────
const evpAcc = new Map();

function hookCryptoModule(mod) {
    let ok = false;
    mod.enumerateExports().forEach(exp => {
        if (exp.name === "EVP_DecryptUpdate") {
            Interceptor.attach(exp.address, {
                onEnter(args) {
                    this.ctx    = args[0].toString();
                    this.outPtr = args[1];
                    this.lenPtr = args[2];
                },
                onLeave(ret) {
                    if (ret.toInt32() !== 1) return;
                    try {
                        const w = this.lenPtr.readS32();
                        if (w <= 0 || w > 50*1024*1024) return;
                        const chunk = new Uint8Array(this.outPtr.readByteArray(w));
                        if (!evpAcc.has(this.ctx)) evpAcc.set(this.ctx, []);
                        evpAcc.get(this.ctx).push(chunk);
                        if (w > 10000) console.log("[EVP_DecryptUpdate] " + mod.base +
                            " ctx=..." + this.ctx.slice(-6) + " written=" + w);
                    } catch(_) {}
                }
            });
            ok = true;
        }
        if (exp.name === "EVP_DecryptFinal_ex") {
            Interceptor.attach(exp.address, {
                onEnter(args) { this.ctx = args[0].toString(); },
                onLeave(ret) {
                    if (ret.toInt32() !== 1) return;
                    const chunks = evpAcc.get(this.ctx) || [];
                    evpAcc.delete(this.ctx);
                    if (!chunks.length) return;
                    const total = chunks.reduce((s,c) => s+c.length, 0);
                    const full = new Uint8Array(total);
                    let off = 0;
                    for (const c of chunks) { full.set(c, off); off += c.length; }
                    sendBuf("EVP_Decrypt(" + mod.base + ")", "AES-GCM", full);
                }
            });
        }
    });
    if (ok) console.log("[+] EVP hooked: " + mod.name + "@" + mod.base);
}
Process.enumerateModules().filter(m => m.name === "libcrypto.so").forEach(hookCryptoModule);

// ── 3. Java Cipher (all large outputs) ───────────────────────────────────────
Java.perform(function() {
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        function fromJava(jArr) {
            const a = Java.array("byte", jArr);
            const o = new Uint8Array(a.length);
            for (let i = 0; i < a.length; i++) o[i] = a[i] & 0xff;
            return o;
        }
        const orig1 = Cipher.doFinal.overload("[B");
        orig1.implementation = function(input) {
            const r = orig1.call(this, input);
            if (r && r.length >= MIN_DUMP_SIZE)
                sendBuf("Java.Cipher", this.getAlgorithm(), fromJava(r));
            return r;
        };
        console.log("[+] Java Cipher.doFinal hooked");
    } catch(e) { console.log("[-] Java Cipher: " + e); }

    // ── 4. HttpURLConnection: capture rpc2 response stream ───────────────────
    // Hook getInputStream(), wrap it to tee all bytes for rpc2 URLs
    try {
        const HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsConn.getInputStream.implementation = function() {
            const stream = this.getInputStream();
            try {
                const url = this.getURL().toString();
                if (!url.includes("rpc2") && !url.includes("ichigo")) return stream;

                console.log("[HttpsConn] getInputStream for: " + url);
                // Read entire response into byte array then re-wrap in a new stream
                const ByteArrayOS = Java.use("java.io.ByteArrayOutputStream");
                const baos = ByteArrayOS.$new();
                const buf  = Java.array("byte", new Array(65536).fill(0));
                let n;
                while ((n = stream.read(buf)) !== -1) {
                    baos.write(buf, 0, n);
                }
                const allBytes = baos.toByteArray();
                console.log("[HttpsConn] rpc2 response len=" + allBytes.length);
                sendBuf("HttpsConn.rpc2.raw", url, fromJavaArr(allBytes));

                // Return a new stream wrapping the captured bytes
                const ByteArrayIS = Java.use("java.io.ByteArrayInputStream");
                return ByteArrayIS.$new(allBytes);
            } catch(e2) {
                console.log("[HttpsConn] tee error: " + e2);
                return stream;
            }
        };

        function fromJavaArr(jArr) {
            const a = Java.array("byte", jArr);
            const o = new Uint8Array(a.length);
            for (let i = 0; i < a.length; i++) o[i] = a[i] & 0xff;
            return o;
        }
        console.log("[+] HttpsURLConnection.getInputStream hooked");
    } catch(e) { console.log("[-] HttpsURLConnection hook: " + e); }

    // URL.openConnection for logging
    try {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            const s = this.toString();
            if (s.includes("rpc") || s.includes("ichigo") || s.includes("niantic"))
                console.log("[URL] openConnection: " + s);
            return this.openConnection();
        };
    } catch(e) {}
});

// ── 5. Memory scan (call scan_fb() from REPL after map loads) ─────────────────
global.scan_fb = function() {
    console.log("[*] Scanning for FB headers...");
    let n = 0;
    Process.enumerateRanges("r--").forEach(r => {
        if (r.size < 1000 || r.size > 200*1024*1024) return;
        try {
            Memory.scanSync(r.base, r.size, "14 00 00 00 00 00 0e 00").forEach(m => {
                const b = new Uint8Array(m.address.readByteArray(64));
                console.log("  FB @ " + m.address + " (region " + r.base + " sz=" + r.size + ")");
                console.log("    " + hexOf(b, 64));
                n++;
                // Try to dump if large enough region
                if (r.size >= MIN_DUMP_SIZE) {
                    sendBuf("scan_fb@" + m.address, "FlatBuffers", new Uint8Array(r.base.readByteArray(r.size)));
                }
            });
        } catch(_) {}
    });
    console.log("[*] scan_fb done, found " + n);
};

// ── 6. scan_plaintext: find low-entropy (decrypted) large regions ─────────────
// Also look for FlatBuffers-like root_off in each region header
global.scan_plaintext = function(minSize, maxH) {
    minSize = minSize || 50000;
    maxH    = maxH    || 7.0;     // raised from 5.5 to catch denser data
    console.log("[*] scan_plaintext: H<" + maxH + " regions >= " + minSize + " bytes...");
    let found = 0;
    const perms = ["r--", "rw-", "rwx"];
    const seen  = new Set();
    perms.forEach(p => {
        try { Process.enumerateRanges(p).forEach(r => { if (!seen.has(r.base.toString())) seen.set(r.base.toString(), r); }); }
        catch(_) {}
    });
    // Iterate unique ranges
    Process.enumerateRanges("r--").concat(Process.enumerateRanges("rw-")).concat(Process.enumerateRanges("rwx")).forEach(r => {
        if (r.size < minSize || r.size > 100*1024*1024) return;
        try {
            // Sample 3 x 512-byte windows for entropy estimate
            const freq = new Array(256).fill(0);
            let total = 0;
            for (const off of [0, Math.floor(r.size/2), r.size - 512]) {
                if (off < 0 || off + 512 > r.size) continue;
                const s = new Uint8Array(r.base.add(off).readByteArray(512));
                for (const b of s) freq[b]++;
                total += 512;
            }
            if (total === 0) return;
            let h = 0;
            for (const c of freq) if (c > 0) { const p = c/total; h -= p * Math.log2(p); }
            if (h >= maxH) return;

            const preview = new Uint8Array(r.base.readByteArray(Math.min(64, r.size)));
            const u32 = preview[0]|(preview[1]<<8)|(preview[2]<<16)|(preview[3]<<24);
            const isFB = (u32 > 0 && u32 < 2000);  // possible FlatBuffers root_off
            const tag  = isFB ? " *** FB root_off=" + u32 : "";

            console.log("  H=" + h.toFixed(2) + " sz=" + r.size + " perm=" + r.protection +
                        " @ " + r.base + tag);
            console.log("    " + hexOf(preview, 32));
            found++;
            if (r.size >= minSize) {
                sendBuf("plaintext@" + r.base, "raw_H" + h.toFixed(1), new Uint8Array(r.base.readByteArray(r.size)));
            }
        } catch(_) {}
    });
    console.log("[*] scan_plaintext done: " + found + " regions found");
};

// ── 7. Hook statically-linked BoringSSL inside libNianticLabsPlugin.so ─────────
(function hookNianticCrypto() {
    const plugin = Process.findModuleByName("libNianticLabsPlugin.so");
    if (!plugin) { console.log("[-] libNianticLabsPlugin.so not found"); return; }

    // Get exported EVP_DecryptUpdate — may be a PLT stub (LDR X16,#8; BR X16)
    const pltAddr = Module.findExportByName(null, "EVP_DecryptUpdate");
    if (!pltAddr) { console.log("[-] No exported EVP_DecryptUpdate for reference"); return; }

    // Detect PLT stub: first u32 == 0x58000050 (LDR X16, #8)
    let realAddr = pltAddr;
    try {
        if (Memory.readU32(pltAddr) === 0x58000050) {
            // PLT entry: real GOT pointer is 8 bytes ahead of stub
            realAddr = Memory.readPointer(pltAddr.add(8));
            console.log("[*] PLT stub → real EVP addr: " + realAddr);
        }
    } catch(_) {}

    // Read 12-byte prologue of the real function as scan pattern
    const refArr = new Uint8Array(Memory.readByteArray(realAddr, 12));
    let hexPat = "";
    for (let i = 0; i < 12; i++) hexPat += ("0" + refArr[i].toString(16)).slice(-2) + " ";
    hexPat = hexPat.trimEnd();
    console.log("[*] Real EVP prologue: " + hexPat);

    // Scan only r-x (executable) ranges inside libNianticLabsPlugin.so
    const pluginEnd = plugin.base.add(plugin.size);
    let hooked = 0;
    Process.enumerateRanges("r-x").forEach(r => {
        if (r.base.compare(plugin.base) < 0 || r.base.compare(pluginEnd) >= 0) return;
        console.log("[*] Scanning r-x range in NianticPlugin: " + r.base + " sz=" + r.size);
        try {
            Memory.scanSync(r.base, r.size, hexPat).forEach(m => {
                if (m.address.equals(realAddr)) return;
                console.log("[+] NianticPlugin EVP candidate @ " + m.address);
                Interceptor.attach(m.address, {
                    onEnter(args) {
                        this.ctx    = args[0].toString();
                        this.outPtr = args[1];
                        this.lenPtr = args[2];
                    },
                    onLeave(ret) {
                        if (ret.toInt32() !== 1) return;
                        try {
                            const w = this.lenPtr.readS32();
                            if (w <= 0 || w > 50*1024*1024) return;
                            const chunk = new Uint8Array(this.outPtr.readByteArray(w));
                            if (!evpAcc.has(this.ctx)) evpAcc.set(this.ctx, []);
                            evpAcc.get(this.ctx).push(chunk);
                            if (w > 5000) console.log("[NianticEVP_Update] ctx=..." +
                                this.ctx.slice(-6) + " written=" + w);
                        } catch(_) {}
                    }
                });
                hooked++;
            });
        } catch(e) { console.log("[-] Scan error @ " + r.base + ": " + e); }
    });
    console.log("[*] NianticPlugin EVP scan done: " + hooked + " candidates hooked");
})();

// ── 8. scan_coords: scan all readable memory for Taiwan lat/lon double pairs ────
global.scan_coords = function() {
    console.log("[*] scan_coords: scanning for lat∈[20,27] lon∈[118,125] doubles...");
    let found = 0;
    const perms = ["r--", "rw-"];
    const ranges = [];
    perms.forEach(p => { try { Process.enumerateRanges(p).forEach(r => ranges.push(r)); } catch(_) {} });

    for (const r of ranges) {
        if (r.size < 16 || r.size > 200*1024*1024) continue;
        let data;
        try { data = r.base.readByteArray(r.size); }
        catch(_) { continue; }
        const dv = new DataView(data);
        for (let i = 0; i <= data.byteLength - 16; i += 4) {
            let lat;
            try { lat = dv.getFloat64(i, true); } catch(_) { continue; }
            // NaN passes (lat < 20 || lat > 27) because all NaN comparisons are false
            if (!isFinite(lat) || lat < 20.0 || lat > 27.0) continue;
            for (const delta of [8, 16, -8, -16]) {
                const j = i + delta;
                if (j < 0 || j + 8 > data.byteLength) continue;
                let lon;
                try { lon = dv.getFloat64(j, true); } catch(_) { continue; }
                if (!isFinite(lon) || lon < 118.0 || lon > 125.0) continue;
                console.log("  COORD @ " + r.base.add(i) + " (" + r.protection + ")" +
                    " lat=" + lat.toFixed(6) + " lon=" + lon.toFixed(6) + " Δ=" + delta);
                // Dump 256 bytes of context
                const ctx_off = Math.max(0, i - 32);
                const ctx_len = Math.min(256, data.byteLength - ctx_off);
                const ctx = new Uint8Array(data, ctx_off, ctx_len);
                console.log("    ctx: " + hexOf(ctx, 48));
                found++;
                if (found >= 30) { console.log("  (capped at 30)"); return; }
                break;
            }
        }
    }
    console.log("[*] scan_coords done: " + found + " pairs found");
};

// ── 9. malloc/free hook — captures large buffers just before free() ───────────
(function hookMallocFree() {
    const mallocFn = Module.findExportByName("libc.so", "malloc");
    const freeFn   = Module.findExportByName("libc.so", "free");
    if (!mallocFn || !freeFn) { console.log("[-] malloc/free not in libc.so"); return; }

    Interceptor.attach(mallocFn, {
        onEnter(a) { this.sz = a[0].toUInt32(); },
        onLeave(ret) {
            if (ret.isNull()) return;
            if (trackMalloc && this.sz >= 50000 && this.sz <= 1000000)
                largeAllocs.set(ret.toString(), this.sz);
            else if (trackSmall && this.sz >= 1000 && this.sz < 50000)
                smallAllocs.set(ret.toString(), this.sz);
        }
    });

    Interceptor.attach(freeFn, {
        onEnter(args) {
            const key = args[0].toString();

            // ── large buffer (50KB-1MB): dump if low entropy ──
            const sz = largeAllocs.get(key);
            if (sz) {
                largeAllocs.delete(key);
                if (!capturedAddrs.has(key)) {
                    try {
                        const sample = new Uint8Array(args[0].readByteArray(Math.min(sz, 512)));
                        const freq = new Array(256).fill(0);
                        for (const b of sample) freq[b]++;
                        let h = 0;
                        for (const c of freq) if (c > 0) { const p = c/sample.length; h -= p * Math.log2(p); }
                        const u32 = sample[0]|(sample[1]<<8)|(sample[2]<<16)|(sample[3]<<24);
                        console.log("[pre-free] sz=" + sz + " H=" + h.toFixed(2) + " u32=" + u32 + " @ " + key);
                        if (h < 7.5) {
                            capturedAddrs.add(key);
                            sendBuf("pre_free@" + key, "H" + h.toFixed(1), new Uint8Array(args[0].readByteArray(sz)));
                        }
                    } catch(_) {}
                }
                return;
            }

            // ── small buffer (1KB-50KB): dump if it contains int7 coord pair ──
            const smallSz = smallAllocs.get(key);
            if (!smallSz) return;
            smallAllocs.delete(key);
            if (capturedAddrs.has(key)) return;
            try {
                const bytes = new Uint8Array(args[0].readByteArray(smallSz));
                const dv = new DataView(bytes.buffer);
                let hasCoord = false, hasSmall = false;
                outer: for (let i = 0; i <= bytes.length - 8; i += 4) {
                    const v = dv.getInt32(i, true);
                    if (v < 200_000_000 || v > 270_000_000) continue;
                    for (const delta of [4, 8, -4, -8]) {
                        const j = i + delta;
                        if (j < 0 || j + 4 > bytes.length) continue;
                        const w = dv.getInt32(j, true);
                        if (w >= 1_180_000_000 && w <= 1_255_000_000) { hasCoord = true; break outer; }
                    }
                }
                if (!hasCoord) return;
                for (let i = 0; i <= bytes.length - 4; i += 4) {
                    const v = dv.getInt32(i, true);
                    if (v >= 1 && v <= 200) { hasSmall = true; break; }
                }
                capturedAddrs.add(key);
                const label = (hasSmall ? "mushroom_record" : "coord_buf") + "@" + key;
                console.log("[small-free] " + label + " sz=" + smallSz + " hasType=" + hasSmall);
                sendBufRaw(label, "small", bytes);
            } catch(_) {}
        }
    });
    console.log("[+] malloc/free hooked (tracking when armed)");
})();

// ── 10. scan_int7: scan all readable memory for int32×1e7 Taiwan coord pairs ────
global.scan_int7 = function(cap) {
    cap = cap || 60;
    console.log("[*] scan_int7: lat∈[200M,270M] lon∈[1180M,1255M] int32 pairs (excl. ART)...");
    let found = 0, skippedArt = 0;
    const ranges = [];
    ["r--", "rw-"].forEach(p => { try { Process.enumerateRanges(p).forEach(r => ranges.push(r)); } catch(_) {} });

    for (const r of ranges) {
        if (r.size < 8 || r.size > 200*1024*1024) continue;
        if (isArtAddress(r.base)) { skippedArt++; continue; }
        let data;
        try { data = r.base.readByteArray(r.size); } catch(_) { continue; }
        const dv = new DataView(data);
        const n = data.byteLength;

        for (let i = 0; i <= n - 8; i += 4) {
            let v;
            try { v = dv.getInt32(i, true); } catch(_) { continue; }
            if (v < 200_000_000 || v > 270_000_000) continue;
            for (const delta of [4, 8, -4, -8]) {
                const j = i + delta;
                if (j < 0 || j + 4 > n) continue;
                let w;
                try { w = dv.getInt32(j, true); } catch(_) { continue; }
                if (w >= 1_180_000_000 && w <= 1_255_000_000) {
                    const lat = v / 1e7, lon = w / 1e7;
                    const ctxOff = Math.max(0, i - 24);
                    const ctxLen = Math.min(80, n - ctxOff);
                    const ctx = new Uint8Array(data, ctxOff, ctxLen);
                    // Skip if context looks like a string table (>55% ASCII)
                    if (asciiDensity(ctx, 0, ctxLen) > 0.55) break;
                    console.log("  INT7 @ " + r.base.add(i) + " (" + r.protection + ")" +
                                " lat=" + lat.toFixed(6) + " lon=" + lon.toFixed(6) + " Δ=" + delta);
                    console.log("    ctx: " + hexOf(ctx, 48));
                    found++;
                    if (found >= cap) { console.log("  (capped at " + cap + ")"); return; }
                    break;
                }
            }
        }
    }
    console.log("[*] scan_int7 done: " + found + " pairs found, " + skippedArt + " ART ranges skipped");
};

// ── 11. scan_mushroom_records: int7 lat+lon AND small int (type/size) in same 64B ─
global.scan_mushroom_records = function(cap) {
    cap = cap || 100;
    console.log("[*] scan_mushroom_records: int7 coord + nearby small int (excl. ART/strings)...");
    let found = 0, skippedArt = 0, skippedAscii = 0;
    const ranges = [];
    ["r--", "rw-"].forEach(p => { try { Process.enumerateRanges(p).forEach(r => ranges.push(r)); } catch(_) {} });

    for (const r of ranges) {
        if (r.size < 16 || r.size > 200*1024*1024) continue;
        if (isArtAddress(r.base)) { skippedArt++; continue; }
        let data;
        try { data = r.base.readByteArray(r.size); } catch(_) { continue; }
        const dv = new DataView(data);
        const n = data.byteLength;

        for (let i = 0; i <= n - 8; i += 4) {
            let v;
            try { v = dv.getInt32(i, true); } catch(_) { continue; }
            if (v < 200_000_000 || v > 270_000_000) continue;

            let lonOff = -1;
            for (const delta of [4, 8, -4, -8, 12, -12, 16, -16]) {
                const j = i + delta;
                if (j < 0 || j + 4 > n) continue;
                let w;
                try { w = dv.getInt32(j, true); } catch(_) { continue; }
                if (w >= 1_180_000_000 && w <= 1_255_000_000) { lonOff = j; break; }
            }
            if (lonOff < 0) continue;

            const lat = v / 1e7;
            const lon = dv.getInt32(lonOff, true) / 1e7;
            const ctxOff = Math.max(0, Math.min(i, lonOff) - 32);
            const ctxLen = Math.min(96, n - ctxOff);
            const ctx = new Uint8Array(data, ctxOff, ctxLen);

            // Skip if the 96-byte window looks like a string table (>50% ASCII printable)
            if (asciiDensity(ctx, 0, ctxLen) > 0.50) { skippedAscii++; continue; }

            const searchStart = Math.max(0, Math.min(i, lonOff) - 32);
            const searchEnd   = Math.min(n - 4, Math.max(i, lonOff) + 36);
            const smallInts   = [];
            for (let k = searchStart; k <= searchEnd; k += 4) {
                if ((k >= i && k < i + 4) || (k >= lonOff && k < lonOff + 4)) continue;
                let sv;
                try { sv = dv.getInt32(k, true); } catch(_) { continue; }
                if (sv >= 1 && sv <= 200) smallInts.push({ rel: k - i, val: sv });
            }
            if (smallInts.length === 0) continue;

            console.log("  MUSHROOM @ " + r.base.add(i) + " (" + r.protection + ")" +
                        " lat=" + lat.toFixed(6) + " lon=" + lon.toFixed(6));
            for (const si of smallInts)
                console.log("    small[" + (si.rel >= 0 ? "+" : "") + si.rel + "] = " + si.val);
            console.log("    ctx: " + hexOf(ctx, 64));

            found++;
            if (found >= cap) { console.log("  (capped at " + cap + ")"); return; }
        }
    }
    console.log("[*] scan_mushroom_records done: " + found + " candidates" +
                " (skipped: " + skippedArt + " ART, " + skippedAscii + " string-table)");
};

// shared: multi-line hexdump, skip all-zero 16B rows, mark relative offsets
function hexBlock(data, base_rel) {
    const lines = [];
    for (let off = 0; off + 16 <= data.length; off += 16) {
        let allZero = true;
        for (let k = 0; k < 16; k++) if (data[off + k]) { allZero = false; break; }
        if (allZero) continue;
        const rel = base_rel + off;
        const tag = (rel >= 0 ? "+" : "") + rel;
        lines.push("  " + tag.padStart(5) + "  " + hexOf(data.slice(off, off + 16), 16));
    }
    return lines.join("\n");
}

// ── 12. scan_mushroom_objects: rw- only, Layout-A IL2CPP objects, de-duped by [+56] ──
// Layout A pattern (confirmed mushroom C# instances):
//   [-16]=null (monitor)  [-8]=ptr (shared config)
//   [+16]=null  [+24]=ptr (class meta, shared)  [+32]=null  [+40]=int32 1/2/4  [+56]=ptr (per-instance)
// Only unique [+56] values are shown — eliminates render/cache copies of same instance.
//
// Usage: scan_mushroom_objects(cap, latCenter, latRadius, lonCenter, lonRadius)
//   latRadius/lonRadius default 0.002; pass 0 for exact match
// Example: scan_mushroom_objects(20, 25.034, 0.001, 121.564, 0.001)
global.scan_mushroom_objects = function(cap, latCenter, latRadius, lonCenter, lonRadius, typeFilter, _collect) {
    cap = cap || 50;
    // allow exact-0 radius
    latRadius = (latRadius === undefined || latRadius === null) ? 0.002 : latRadius;
    lonRadius = (lonRadius === undefined || lonRadius === null) ? 0.002 : lonRadius;
    // typeFilter: "AB" = skip Type-C (useful when Type-C floods the results)
    const skipC = (typeFilter && typeFilter.toUpperCase().indexOf("C") === -1);
    const filterCoord = (latCenter !== undefined && lonCenter !== undefined);
    if (filterCoord)
        console.log("[*] scan_mushroom_objects — lat " + latCenter + " ±" + latRadius +
                    "  lon " + lonCenter + " ±" + lonRadius +
                    (skipC ? "  [AB only]" : "") + "  (Layout-A, de-duped)");
    else
        console.log("[*] scan_mushroom_objects (rw-, Layout-A, de-duped)" + (skipC ? " [AB only]" : "") + "...");
    let found = 0, skippedArt = 0, skippedLayout = 0, skippedDup = 0, skippedC = 0;
    const seenInst = new Set();   // de-dup by [+56] ptr value

    // dynamic lat/lon pre-filter bounds (supports non-Taiwan coordinates)
    const margin = 0.05;
    const latMin = filterCoord ? latCenter - Math.max(latRadius, margin) : -90.0;
    const latMax = filterCoord ? latCenter + Math.max(latRadius, margin) :  90.0;
    const lonMin = filterCoord ? lonCenter - Math.max(lonRadius, margin) : -180.0;
    const lonMax = filterCoord ? lonCenter + Math.max(lonRadius, margin) :  180.0;

    const ranges = [];
    try { Process.enumerateRanges("rw-").forEach(r => ranges.push(r)); } catch(_) {}

    for (const r of ranges) {
        if (r.size < 24 || r.size > 200*1024*1024) continue;
        let data;
        try { data = r.base.readByteArray(r.size); } catch(_) { continue; }
        const dv = new DataView(data);
        const n = data.byteLength;

        for (let i = 0; i <= n - 16; i += 8) {
            let lat;
            try { lat = dv.getFloat64(i, true); } catch(_) { continue; }
            if (!isFinite(lat) || lat < latMin || lat > latMax) continue;
            if (filterCoord && Math.abs(lat - latCenter) > latRadius) continue;

            let lonOff = -1, lon = 0;
            for (const delta of [8, 16, -8, -16, 24, -24]) {
                const j = i + delta;
                if (j < 0 || j + 8 > n) continue;
                let v;
                try { v = dv.getFloat64(j, true); } catch(_) { continue; }
                if (isFinite(v) && v >= lonMin && v <= lonMax) { lon = v; lonOff = j; break; }
            }
            if (lonOff < 0) continue;
            if (filterCoord && Math.abs(lon - lonCenter) > lonRadius) continue;

            // ── IL2CPP mushroom object structural check ────────────────────────
            // Three confirmed layouts (heap ptr range 0x60-0x7f on this device):
            //   Type-A: [+16]=null, [+24]=class-ptr, [+32]=null, [+40]=flag∈[1,20], [+56]=inst-ptr
            //   Type-B: [+16]=null, [+24]=null,      [+32]=flag∈[1,20], [+40]=null, [+56]=inst-ptr
            //   Type-C: [+16]=null, [+24]=heap-ptr,  [+32]=null, [+40]=heap-ptr, [+48]={A,B} A,B∈[1,20]
            if (i + 64 > n || i < 8) { skippedLayout++; continue; }
            if (dv.getFloat64(i + 16, true) !== 0) { skippedLayout++; continue; }

            const flag40    = dv.getInt32(i + 40, true);
            const flag40hi  = dv.getUint32(i + 44, true);
            const flag32    = dv.getInt32(i + 32, true);
            const flag32hi  = dv.getUint32(i + 36, true);
            const ptr24hi   = dv.getUint32(i + 28, true);
            const ptr40hi   = dv.getUint32(i + 44, true);   // high 4B of [+40]
            const ptr56hi   = dv.getUint32(i + 60, true);
            const pair48a   = dv.getInt32(i + 48, true);    // A: int32 at [+48..+51]
            const pair48b   = dv.getInt32(i + 52, true);    // B: int32 at [+52..+55]

            // heap pointer check: high 4 bytes in [0x60, 0x7f]
            const isHeapPtr = (hi) => hi >= 0x60 && hi <= 0x7f;

            let flag, flagOff, typeStr, dedupKey;
            if (flag40 >= 1 && flag40 <= 20 && flag40hi === 0 && isHeapPtr(ptr24hi) && isHeapPtr(ptr56hi)) {
                // Type-A: flag at [+40]
                flag = flag40; flagOff = 40;
                typeStr = "A";
                dedupKey = ptr56hi.toString(16) + "_" + dv.getUint32(i + 56, true).toString(16);
            } else if (flag32 >= 1 && flag32 <= 20 && flag32hi === 0 &&
                       flag40 === 0 && flag40hi === 0 && isHeapPtr(ptr56hi)) {
                // Type-B: flag at [+32], [+40]=null
                flag = flag32; flagOff = 32;
                typeStr = "B";
                dedupKey = ptr56hi.toString(16) + "_" + dv.getUint32(i + 56, true).toString(16);
            } else if (isHeapPtr(ptr24hi) && isHeapPtr(ptr40hi) &&
                       dv.getFloat64(i + 32, true) === 0 &&
                       dv.getFloat64(i + 56, true) === 0 &&
                       pair48a >= 1 && pair48a <= 20 &&
                       pair48b >= 1 && pair48b <= 20) {
                // Type-C: {A,B} at [+48], [+56]=null, heap ptrs at [+24] and [+40]
                // A=crystal(1=normal,4=crystal) B=size(1=small,3=large) — color unknown
                flag = pair48a; flagOff = 48;
                typeStr = "C";
                dedupKey = ptr40hi.toString(16) + "_" + flag40.toString(16);
            } else { skippedLayout++; continue; }

            if (skipC && typeStr === "C") { skippedC++; continue; }

            const objAddr = r.base.add(i);

            // De-duplicate by unique instance ptr
            if (seenInst.has(dedupKey)) { skippedDup++; continue; }
            seenInst.add(dedupKey);

            // For Type-C: {A,B} already in flag/pair48b; for A/B: read type klass + scan for size
            let instInfo = "";
            let objSize = 0, objColorId = 0, objCrystal = 1;
            if (typeStr === "C") {
                objCrystal = pair48a; objSize = pair48b;
                instInfo = "  {" + pair48a + "," + pair48b + "}";
            } else {
                try {
                    const instPtr = objAddr.add(56).readPointer();
                    const typeKlass = instPtr.readPointer();   // inst[+0] = klass ptr = mushroom type ID
                    instInfo = "  type=" + typeKlass;
                } catch(_) {}
                // Scan [+64..+160] for small int32s (size/crystal field candidates)
                if (i + 168 <= n) {
                    const extras = [];
                    // Type-B size confirmed at [+144]; Type-A at [+96] — use fixed offset per type
                    const sizeOff = typeStr === "B" ? 144 : 96;
                    for (let off = 64; off <= 160; off += 8) {
                        const lo = dv.getInt32(i + off, true);
                        const hi = dv.getInt32(i + off + 4, true);
                        if (lo >= 1 && lo <= 20 && hi === 0) {
                            extras.push("[+" + off + "]=" + lo);
                        } else if (lo >= 1 && lo <= 20 && hi >= 1 && hi <= 20) {
                            extras.push("[+" + off + "]={" + lo + "," + hi + "}");
                            // Read size only from the confirmed offset to avoid false overrides
                            if (off === sizeOff && (lo === 1 || lo === 4) && hi >= 1 && hi <= 3) {
                                objCrystal = lo; objSize = hi;
                            }
                            if (off === 152) { objColorId = lo; }
                        }
                    }
                    if (extras.length) instInfo += "  " + extras.join(" ");
                }
            }

            const sizeLabel = (sz) => sz === 1 ? "small" : sz === 2 ? "normal" : sz === 3 ? "large" : ("size=" + sz);
            const crystalLabel = (a) => a === 4 ? "crystal" : "normal";
            let flagLabel;
            if (typeStr === "C") {
                flagLabel = "  (" + crystalLabel(pair48a) + " " + sizeLabel(pair48b) + ")";
            } else {
                flagLabel = flag === 4 ? " (crystal)" : flag === 1 ? " (normal)" : (" (flag=" + flag + ")");
            }
            console.log("OBJ[" + typeStr + "] @ " + objAddr +
                        "  lat=" + lat.toFixed(6) + "  lon=" + lon.toFixed(6) +
                        "  [+" + flagOff + "]=" + flag + flagLabel + instInfo);

            if (_collect) _collect.push({
                lat: lat, lon: lon,
                size: objSize, colorId: objColorId, crystal: objCrystal,
                type: typeStr, addr: objAddr.toString()
            });

            found++;
            if (found >= cap) {
                console.log("(capped at " + cap + ")");
                console.log("[*] skipped: layout=" + skippedLayout + " dup=" + skippedDup + (skippedC ? " C=" + skippedC : ""));
                return;
            }
        }
    }
    console.log("[*] done: " + found + " objects  (skipped layout=" + skippedLayout + " dup=" + skippedDup + (skippedC ? " C=" + skippedC : "") + ")");
};

// ── 12c. scan_exact: find exact float64 lat+lon pair, dump raw context ──────────
// No layout assumptions — shows all rw- hits regardless of surrounding structure.
// Usage: scan_exact(lat, lon)
// Example: scan_exact(25.023462, 121.500382)
global.scan_exact = function(latVal, lonVal) {
    // serialise latVal to 8 bytes for fast byte-level scanning
    const tmp = Memory.alloc(8);
    tmp.writeDouble(latVal);
    const latBytes = new Uint8Array(tmp.readByteArray(8));

    console.log("[*] scan_exact lat=" + latVal + "  lon=" + lonVal);
    let found = 0;
    const artRanges = getArtRanges();
    const ranges = [];
    try { Process.enumerateRanges("rw-").forEach(r => ranges.push(r)); } catch(_) {}

    for (const r of ranges) {
        if (r.size < 8 || r.size > 200*1024*1024) continue;
        if (isArtAddress(r.base)) continue;
        let data;
        try { data = r.base.readByteArray(r.size); } catch(_) { continue; }
        const arr = new Uint8Array(data);
        const dv  = new DataView(data);
        const n   = arr.length;

        for (let i = 0; i <= n - 8; i++) {
            if (arr[i] !== latBytes[0] || arr[i+1] !== latBytes[1]) continue;
            let match = true;
            for (let k = 2; k < 8; k++) if (arr[i+k] !== latBytes[k]) { match = false; break; }
            if (!match) continue;

            // look for lon within ±64 bytes (8-byte aligned)
            let lonDelta = 0, lonFound = false;
            for (let d = -64; d <= 64; d += 8) {
                const j = i + d;
                if (j < 0 || j + 8 > n || d === 0) continue;
                const v = dv.getFloat64(j, true);
                if (Math.abs(v - lonVal) < 1e-6) { lonDelta = d; lonFound = true; break; }
            }
            if (!lonFound) continue;

            const addr = r.base.add(i);
            console.log("HIT @ " + addr + "  lon at lat" + (lonDelta >= 0 ? "+" : "") + lonDelta);
            const ctxOff = Math.max(0, i - 64);
            const ctxLen = Math.min(160, n - ctxOff);
            console.log(hexBlock(new Uint8Array(data, ctxOff, ctxLen), ctxOff - i));
            console.log("");
            if (++found >= 20) { console.log("(capped at 20)"); return; }
        }
    }
    console.log("[*] done: " + found + " hits");
};

// ── 12b. read_obj: read fields from a known OBJ address (lat field address) ──
// Usage: read_obj("0x...")
// Dumps the crystal flag at [+40] and the per-instance data ptr at [+56].
// [+24] is class-level metadata shared by all instances; [+56] varies per object.
global.read_obj = function(addrStr) {
    const objAddr = ptr(addrStr);
    let lat, lon;
    try { lat = objAddr.readDouble(); } catch(e) { console.log("[-] bad address: " + e); return; }
    try { lon = objAddr.add(8).readDouble(); } catch(_) { lon = NaN; }
    console.log("OBJ @ " + addrStr + "  lat=" + lat.toFixed(6) + "  lon=" + (isFinite(lon) ? lon.toFixed(6) : "?"));

    // [+24]: class-level ptr (shared across all instances of same class)
    try { console.log("  [+24] class ptr = " + objAddr.add(24).readPointer()); } catch(_) {}

    // [+40]: crystal/size flag
    try {
        const v = objAddr.add(40).readS32();
        const label = v === 4 ? "  ← crystal" : v === 1 ? "  ← normal/small?" : v === 2 ? "  ← large?" : "";
        console.log("  [+40] flag=" + v + label);
    } catch(_) {}

    // [+56]: per-instance data ptr (varies per object — likely holds color/size)
    try {
        const instPtr = objAddr.add(56).readPointer();
        if (instPtr.isNull()) {
            console.log("  [+56] inst ptr = NULL");
        } else {
            console.log("  [+56] inst ptr = " + instPtr);
            const raw = new Uint8Array(instPtr.readByteArray(64));
            const dv2 = new DataView(raw.buffer);
            const parts = [];
            for (let k = 0; k + 8 <= 64; k += 8) {
                const lo = dv2.getUint32(k, true);
                const hi = dv2.getUint32(k + 4, true);
                if (lo === 0 && hi === 0) continue;
                if (lo > 100000 || hi > 100000) { parts.push("[+" + k + "]=ptr(" + instPtr.add(k) + ")"); continue; }
                const a = dv2.getInt32(k, true), b = dv2.getInt32(k + 4, true);
                parts.push(hi === 0 ? "[+" + k + "]=" + a : "[+" + k + "]={" + a + "," + b + "}");
            }
            console.log("  inst: " + (parts.length ? parts.join("  ") : "(all zero or pointers)"));
        }
    } catch(e) { console.log("  [+56] read ptr failed: " + e); }
};

// ── 13. dump_at: hexdump + int32 parse around a known address ───────────────────
global.dump_at = function(addrStr, before, after) {
    before = before || 80;
    after  = after  || 160;
    const base = ptr(addrStr).sub(before);
    const len  = before + after;
    let data;
    try { data = new Uint8Array(base.readByteArray(len)); }
    catch(e) { console.log("[-] read failed: " + e); return; }
    const dv = new DataView(data.buffer);
    console.log("dump_at " + addrStr + "  -" + before + " .. +" + after);
    console.log(hexBlock(data, -before));
    console.log("--- int32 pairs @ 8B stride (non-pointer, non-zero) ---");
    for (let off = 0; off + 8 <= len; off += 8) {
        const lo = dv.getUint32(off, true);
        const hi = dv.getUint32(off + 4, true);
        if (lo === 0 && hi === 0) continue;
        if (lo > 100000) continue;        // pointer: low-half is always large
        if (hi > 100000) continue;        // sanity check on high-half
        const rel = off - before;
        const f64 = dv.getFloat64(off, true);
        const isCoord = isFinite(f64) && ((f64 >= 20 && f64 <= 27) || (f64 >= 118 && f64 <= 126));
        const a = dv.getInt32(off, true), b = dv.getInt32(off + 4, true);
        if (isCoord)
            console.log("  [" + (rel >= 0 ? "+" : "") + rel + "]  f64=" + f64.toFixed(6) + "  ← coord");
        else if (hi === 0)
            console.log("  [" + (rel >= 0 ? "+" : "") + rel + "]  int32=" + a);
        else
            console.log("  [" + (rel >= 0 ? "+" : "") + rel + "]  {" + a + ", " + b + "}");
    }
};

// ── find_mushrooms: human-friendly filter wrapper ─────────────────────────────
// Usage: find_mushrooms("large")  /  find_mushrooms("large","red")
// size: "small"|"normal"|"large"   color: "red"|"yellow"|"pink"|"fire"|"poisonous"|...
global.find_mushrooms = function(sizeStr, colorStr) {
    const SIZE_MAP   = {small:1, normal:2, large:3};
    const COLOR_MAP  = {red:2, yellow:6, pink:9, electric:9, fire:11, crystal:13, poisonous:18, white:18};
    const targetSize  = sizeStr  ? (SIZE_MAP[sizeStr.toLowerCase()]  || 0) : 0;
    const targetColor = colorStr ? (COLOR_MAP[colorStr.toLowerCase()] || 0) : 0;

    const results = [];
    scan_mushroom_objects(500, undefined, undefined, undefined, undefined, "AB", results);

    const filtered = results.filter(function(m) {
        if (targetSize  && m.size    !== targetSize)  return false;
        if (targetColor && m.colorId !== targetColor) return false;
        return true;
    });
    const SIZE_LABEL  = {1:"small", 2:"normal", 3:"large"};
    const COLOR_LABEL = {2:"red", 6:"yellow", 9:"pink/electric", 11:"fire", 18:"poisonous"};
    filtered.forEach(function(m) {
        console.log("MUSHROOM  lat=" + m.lat.toFixed(6) + "  lon=" + m.lon.toFixed(6) +
                    "  size=" + (SIZE_LABEL[m.size] || m.size) +
                    "  color=" + (COLOR_LABEL[m.colorId] || (m.colorId || "?")) +
                    (m.crystal === 4 ? " (crystal)" : ""));
    });
    console.log("[find_mushrooms] " + filtered.length + " / " + results.length + " shown");
};

// Expose functions to Python via rpc.exports
rpc.exports = {
    scanFb:               function() { scan_fb(); },
    scanPlaintext:        function(minSize) { scan_plaintext(minSize); },
    scanCoords:           function() { scan_coords(); },
    scanInt7:             function() { scan_int7(); },
    scanMushroomRecords:  function() { scan_mushroom_records(); },
    scanMushroomObjects:  function() { scan_mushroom_objects(); },
    dumpAt:               function(addr, before, after) { dump_at(addr, before, after); },
    readObj:              function(addr) { read_obj(addr); },
    scanExact:            function(lat, lon) { scan_exact(lat, lon); },
    evalJs:               function(code) { return eval(code); },
    // Returns JSON array of mushroom objects for the Python scanner
    scanMushrooms: function(lat, lon, radius) {
        const results = [];
        scan_mushroom_objects(500, lat, radius, lon, radius, "AB", results);
        return JSON.stringify(results);
    },
};

console.log("[*] All hooks loaded. Waiting for rpc2...");
console.log("[*] REPL: scan_mushroom_objects(cap,lat,latR,lon,lonR) | scan_exact(lat,lon) | read_obj(addr) | dump_at(addr)");
console.log("[*] Flags: trackMalloc (50KB-1MB large bufs) | trackSmall (1KB-50KB coord bufs)");

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
        const maps = require("fs").readFileSync("/proc/self/maps", "utf8");
        for (const line of maps.split("\n")) {
            // Match dalvik-main space, dalvik-large object space, .art files, etc.
            if (!line.includes("dalvik-") && !line.includes(".art ") &&
                !line.includes("jit-code-cache") && !line.includes("indirect ref")) continue;
            const m = line.match(/^([0-9a-f]+)-([0-9a-f]+)/);
            if (!m) continue;
            _artRanges.push({ base: ptr(m[1]), end: ptr(m[2]) });
        }
    } catch(_) {}
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
                    console.log("[SSL_read] large rpc2 chunk (" + full.length + " bytes) — arming malloc+small tracker, scan_coords in 5s");
                    setTimeout(function() {
                        trackMalloc = false;
                        trackSmall  = false;
                        console.log("[auto-scan] running scan_coords + scan_int7 + scan_mushroom_records...");
                        scan_coords();
                        scan_int7();
                        scan_mushroom_records();
                        rpc2LargeDetected = false;
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

// Expose functions to Python via rpc.exports
rpc.exports = {
    scanFb:              function() { scan_fb(); },
    scanPlaintext:       function(minSize) { scan_plaintext(minSize); },
    scanCoords:          function() { scan_coords(); },
    scanInt7:            function() { scan_int7(); },
    scanMushroomRecords: function() { scan_mushroom_records(); },
    evalJs:              function(code) { return eval(code); },
};

console.log("[*] All hooks loaded. Waiting for rpc2...");
console.log("[*] REPL: scan_coords() | scan_int7() | scan_mushroom_records() | scan_fb() | scan_plaintext() | eval(<js>)");
console.log("[*] Flags: trackMalloc (50KB-1MB large bufs) | trackSmall (1KB-50KB coord bufs)");

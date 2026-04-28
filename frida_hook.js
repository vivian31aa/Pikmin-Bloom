/**
 * frida_hook.js
 * Capture Pikmin Bloom rpc2 response (encrypted) and decrypted payload.
 * Confirmed: game uses java.net.URL → native TLS → libNianticLabsPlugin.so decrypt
 */

"use strict";

const MIN_DUMP_SIZE = 50000;
let dumpIndex = 0;

function hexOf(arr, n) {
    n = Math.min(n || 32, arr.length);
    let s = "";
    for (let i = 0; i < n; i++) s += ("0" + (arr[i] & 0xff).toString(16)).slice(-2) + " ";
    return s.trimEnd();
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

                // If this looks like a large rpc2 response, schedule memory scan
                // after a 3-second delay (time for game to decrypt and store in memory)
                if (full.length > 40000 && !rpc2LargeDetected) {
                    rpc2LargeDetected = true;
                    console.log("[SSL_read] large response detected (" + full.length + " bytes) — auto-scan in 3s");
                    setTimeout(function() {
                        console.log("[auto-scan] starting scan_plaintext after rpc2...");
                        scan_plaintext(50000);
                        scan_fb();
                        rpc2LargeDetected = false;  // allow next trigger
                    }, 3000);
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

// Expose functions to Python via rpc.exports
rpc.exports = {
    scanFb:          function() { scan_fb(); },
    scanPlaintext:   function(minSize) { scan_plaintext(minSize); },
    evalJs:          function(code) { return eval(code); },
};

console.log("[*] All hooks loaded. Waiting for rpc2...");
console.log("[*] REPL: scan_fb() | scan_plaintext() | eval(<js>)");

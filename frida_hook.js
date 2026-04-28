/**
 * frida_hook.js
 * Hook Pikmin Bloom's rpc2 response decryption.
 *
 * Usage:
 *   frida -U -n "Pikmin Bloom" -l frida_hook.js
 *   frida -U --attach-name "com.nianticlabs.pikminbloom" -l frida_hook.js
 *
 * What this does:
 *   1. Hook javax.crypto.Cipher.doFinal() — catches Java-layer AES decrypt
 *   2. Hook OkHttp ResponseBody.bytes() — catches raw HTTP response body
 *   3. Search memory for the decrypted protobuf/FlatBuffers signature
 *
 * Install Frida on device:
 *   adb push frida-server-XX-android-arm64 /data/local/tmp/frida-server
 *   adb shell chmod 755 /data/local/tmp/frida-server
 *   adb shell /data/local/tmp/frida-server &
 *
 * Install frida-tools on PC:
 *   pip install frida-tools
 */

"use strict";

// ── Config ───────────────────────────────────────────────────────────────────
const TARGET_HOST = "ichigo-rel";   // partial match for rpc2 host
const MIN_DUMP_SIZE = 1000;         // ignore tiny decrypted buffers
const SAVE_DIR = "/sdcard/pikmin_decrypted";

// ── Helpers ───────────────────────────────────────────────────────────────────
function hexpreview(buf, n) {
    n = Math.min(n || 32, buf.byteLength);
    let s = "";
    for (let i = 0; i < n; i++) s += ("0" + buf[i].toString(16)).slice(-2) + " ";
    return s.trimEnd();
}

function saveToFile(name, bytes) {
    try {
        const f = new File(SAVE_DIR + "/" + name, "wb");
        f.write(bytes);
        f.flush();
        f.close();
        return true;
    } catch (e) {
        return false;
    }
}

function mkdir(dir) {
    try { new File(dir, "w").close(); } catch(_) {}
    try {
        Java.perform(() => {
            const File = Java.use("java.io.File");
            File.$new(dir).mkdirs();
        });
    } catch(_) {}
}

let dumpIndex = 0;

// ── 1. Hook javax.crypto.Cipher.doFinal ──────────────────────────────────────
Java.perform(function() {
    mkdir(SAVE_DIR);
    console.log("[*] Pikmin Bloom Frida hook loaded");
    console.log("[*] Saving decrypted dumps to " + SAVE_DIR);

    try {
        const Cipher = Java.use("javax.crypto.Cipher");

        // doFinal(byte[]) — decrypt whole buffer at once
        Cipher.doFinal.overload("[B").implementation = function(input) {
            const result = this.doFinal(input);
            const alg = this.getAlgorithm();
            const mode = this.getBlockSize ? this.getBlockSize() : 0;

            if (result && result.length >= MIN_DUMP_SIZE) {
                const idx = dumpIndex++;
                console.log("\n[Cipher.doFinal] alg=" + alg +
                            "  input_len=" + input.length +
                            "  output_len=" + result.length);
                const preview = hexpreview(result, 32);
                console.log("  output preview: " + preview);

                // Check for FlatBuffers root offset signature
                if (result.length >= 8) {
                    const u32 = (result[0] & 0xff) |
                                ((result[1] & 0xff) << 8) |
                                ((result[2] & 0xff) << 16) |
                                ((result[3] & 0xff) << 24);
                    if (u32 < 1000) {
                        console.log("  ** Possible FlatBuffers root offset: " + u32);
                    }
                }

                const fname = "cipher_" + idx + "_" + result.length + ".bin";
                if (saveToFile(fname, result)) {
                    console.log("  Saved: " + SAVE_DIR + "/" + fname);
                } else {
                    console.log("  [!] Save failed (no storage permission?)");
                }
            }
            return result;
        };

        // doFinal(byte[], int, int) — decrypt with offset/length
        Cipher.doFinal.overload("[B", "int", "int").implementation = function(input, offset, len) {
            const result = this.doFinal(input, offset, len);
            const alg = this.getAlgorithm();

            if (result && result.length >= MIN_DUMP_SIZE) {
                const idx = dumpIndex++;
                console.log("\n[Cipher.doFinal/3] alg=" + alg +
                            "  input_len=" + len +
                            "  output_len=" + result.length);
                console.log("  output preview: " + hexpreview(result, 32));

                const fname = "cipher3_" + idx + "_" + result.length + ".bin";
                saveToFile(fname, result);
                console.log("  Saved: " + SAVE_DIR + "/" + fname);
            }
            return result;
        };

        console.log("[+] javax.crypto.Cipher.doFinal hooked");
    } catch(e) {
        console.log("[-] Cipher hook failed: " + e);
    }

    // ── 2. Hook OkHttp3 response body ────────────────────────────────────────
    try {
        // okhttp3.ResponseBody.bytes() returns the raw response bytes
        const ResponseBody = Java.use("okhttp3.ResponseBody");
        ResponseBody.bytes.implementation = function() {
            const result = this.bytes();

            // Try to get the URL from the call stack
            // (limited; just log size + preview)
            if (result && result.length >= MIN_DUMP_SIZE) {
                const idx = dumpIndex++;
                console.log("\n[OkHttp ResponseBody.bytes] len=" + result.length);
                console.log("  preview: " + hexpreview(result, 32));

                const fname = "http_" + idx + "_" + result.length + ".bin";
                saveToFile(fname, result);
                console.log("  Saved: " + SAVE_DIR + "/" + fname);
            }
            return result;
        };
        console.log("[+] OkHttp3 ResponseBody.bytes hooked");
    } catch(e) {
        console.log("[-] OkHttp hook failed (not present or different class): " + e);
    }

    // ── 3. Hook native decryption via AES key schedule search ────────────────
    // Uncomment if Java hooks don't catch anything (native code path)
    /*
    Process.enumerateModules().forEach(mod => {
        if (mod.name.toLowerCase().includes("lightship") ||
            mod.name.toLowerCase().includes("pikmin") ||
            mod.name.toLowerCase().includes("vps")) {
            console.log("[*] Found candidate native module: " + mod.name + " @ " + mod.base);
        }
    });
    */

    // ── 4. Memory scan: find decrypted FlatBuffers after game init ────────────
    // Call this manually from the REPL: scan_memory()
    global.scan_memory = function() {
        console.log("[*] Scanning process memory for FlatBuffers headers...");
        let found = 0;

        Process.enumerateRanges("r--").forEach(range => {
            if (range.size < 1000 || range.size > 100 * 1024 * 1024) return;

            try {
                // Search for common FlatBuffers root offset patterns
                // Root offset for a ~315KB buffer would be 14, 20, or similar small values
                for (let pattern of [
                    "14 00 00 00 00 00 0e 00",   // outer FB header (exact match)
                    "14 00 00 00 00 00 0c 00",
                    "08 00 00 00 00 00 06 00",
                ]) {
                    Memory.scanSync(range.base, range.size, pattern).forEach(match => {
                        const ptr = match.address;
                        const u32_0 = ptr.readU32();
                        if (u32_0 < 200) {  // plausible FB root offset
                            const preview = hexpreview(ptr.readByteArray(32), 32);
                            console.log("  FB-like @ " + ptr + " (" + range.file + "): " + preview);
                            found++;
                        }
                    });
                }
            } catch(_) {}
        });
        console.log("[*] Scan done, found " + found + " candidates");
    };

    console.log("[*] REPL: call scan_memory() to search process memory");
    console.log("[*] Waiting for rpc2 calls...");
});

// ── 5. Native SSL_write / SSL_read hooks (optional, catches post-TLS data) ──
// Uncomment if you want to see all SSL traffic through BoringSSL
/*
const ssl_read = Module.findExportByName("libssl.so", "SSL_read");
if (ssl_read) {
    Interceptor.attach(ssl_read, {
        onLeave(retval) {
            const n = retval.toInt32();
            if (n > MIN_DUMP_SIZE) {
                const buf = this.context.rsi.readByteArray(n);
                const preview = hexpreview(new Uint8Array(buf), 32);
                console.log("[SSL_read] n=" + n + "  " + preview);
            }
        }
    });
    console.log("[+] SSL_read hooked");
}
*/

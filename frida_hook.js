/**
 * frida_hook.js
 * Hook Pikmin Bloom's rpc2 response decryption.
 * Targets both Java Cipher (decrypt mode only) and native BoringSSL EVP.
 */

"use strict";

const MIN_DUMP_SIZE = 50000;   // only care about buffers > 50KB (rpc2 is ~315KB)
let dumpIndex = 0;

function hexpreview(ptr_or_arr, n) {
    n = n || 32;
    try {
        if (ptr_or_arr instanceof NativePointer) {
            return ptr_or_arr.readByteArray(n) ? hexOf(new Uint8Array(ptr_or_arr.readByteArray(n)), n) : "?";
        }
        return hexOf(ptr_or_arr, n);
    } catch(_) { return "?"; }
}

function hexOf(arr, n) {
    n = Math.min(n || 32, arr.length);
    let s = "";
    for (let i = 0; i < n; i++) s += ("0" + (arr[i] & 0xff).toString(16)).slice(-2) + " ";
    return s.trimEnd();
}

function sendBuf(label, alg, bytes) {
    if (bytes.length < MIN_DUMP_SIZE) return;
    const idx = dumpIndex++;
    const preview = hexOf(bytes, 32);
    console.log("\n[" + label + "] alg=" + alg + "  len=" + bytes.length);
    console.log("  preview: " + preview);

    // FlatBuffers check
    if (bytes.length >= 4) {
        const u32 = bytes[0] | (bytes[1]<<8) | (bytes[2]<<16) | (bytes[3]<<24);
        if (u32 > 0 && u32 < 500) console.log("  ** FlatBuffers root_off=" + u32);
    }

    send({ type: "buffer", index: idx, label: label, alg: alg, len: bytes.length },
         bytes.buffer || bytes);
}

function javaArrayToUint8(jArr) {
    const arr = Java.array("byte", jArr);
    const out = new Uint8Array(arr.length);
    for (let i = 0; i < arr.length; i++) out[i] = arr[i] & 0xff;
    return out;
}

// ── 1. Java Cipher — DECRYPT mode only ───────────────────────────────────────
Java.perform(function() {
    console.log("[*] frida_hook.js loaded");

    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const DECRYPT_MODE = 2;

        Cipher.doFinal.overload("[B").implementation = function(input) {
            const result = this.doFinal(input);
            if (this.getOpmode && this.getOpmode() === DECRYPT_MODE && result && result.length >= MIN_DUMP_SIZE) {
                sendBuf("Java.Cipher", this.getAlgorithm(), javaArrayToUint8(result));
            }
            return result;
        };

        Cipher.doFinal.overload("[B", "int", "int").implementation = function(input, off, len) {
            const result = this.doFinal(input, off, len);
            if (this.getOpmode && this.getOpmode() === DECRYPT_MODE && result && result.length >= MIN_DUMP_SIZE) {
                sendBuf("Java.Cipher/3", this.getAlgorithm(), javaArrayToUint8(result));
            }
            return result;
        };

        console.log("[+] Java Cipher.doFinal hooked (decrypt mode, >" + MIN_DUMP_SIZE + " bytes)");
    } catch(e) {
        console.log("[-] Java Cipher hook failed: " + e);
    }
});

// ── 2. Native BoringSSL — EVP_DecryptFinal_ex ─────────────────────────────────
// Called once per decrypt operation, after EVP_DecryptUpdate fills the buffer.
// int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len)

(function hookBoringSSL() {
    // BoringSSL can be in libcrypto.so or embedded in the app's own .so
    const candidates = ["libcrypto.so", "libssl.so", "libboringssl.so"];
    let hooked = false;

    for (const lib of candidates) {
        const fn = Module.findExportByName(lib, "EVP_DecryptFinal_ex");
        if (!fn) continue;

        Interceptor.attach(fn, {
            onEnter(args) {
                this.outPtr = args[1];
                this.lenPtr = args[2];
            },
            onLeave(ret) {
                if (ret.toInt32() !== 1) return;  // failed
                try {
                    const finalLen = this.lenPtr.readS32();
                    if (finalLen < 0 || finalLen > 10 * 1024 * 1024) return;
                    // The full plaintext was written by EVP_DecryptUpdate calls.
                    // We only get the final block here; use EVP_DecryptUpdate to get all.
                    const bytes = new Uint8Array(this.outPtr.readByteArray(finalLen));
                    if (bytes.length >= 16) {
                        console.log("\n[EVP_DecryptFinal_ex] finalLen=" + finalLen +
                                    "  preview: " + hexOf(bytes, 32));
                    }
                } catch(_) {}
            }
        });
        console.log("[+] EVP_DecryptFinal_ex hooked in " + lib);
        hooked = true;
        break;
    }
    if (!hooked) console.log("[!] EVP_DecryptFinal_ex not found in system libs — searching app libs...");

    // ── 3. EVP_DecryptUpdate — accumulate all plaintext chunks ────────────────
    // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len,
    //                       const uint8_t *in, int in_len)
    const accumulator = new Map();  // ctx → Uint8Array[]

    for (const lib of candidates) {
        const fn = Module.findExportByName(lib, "EVP_DecryptUpdate");
        if (!fn) continue;

        Interceptor.attach(fn, {
            onEnter(args) {
                this.ctx    = args[0].toString();
                this.outPtr = args[1];
                this.lenPtr = args[2];
                this.inLen  = args[4].toInt32();
            },
            onLeave(ret) {
                if (ret.toInt32() !== 1) return;
                try {
                    const written = this.lenPtr.readS32();
                    if (written <= 0 || written > 20 * 1024 * 1024) return;
                    const chunk = new Uint8Array(this.outPtr.readByteArray(written));

                    if (!accumulator.has(this.ctx)) accumulator.set(this.ctx, []);
                    accumulator.get(this.ctx).push(chunk);

                    // If this chunk is large, log it
                    if (written > MIN_DUMP_SIZE) {
                        console.log("[EVP_DecryptUpdate] ctx=" + this.ctx.slice(-8) +
                                    "  written=" + written +
                                    "  preview: " + hexOf(chunk, 32));
                    }
                } catch(_) {}
            }
        });

        // When DecryptFinal succeeds, emit the full accumulated buffer
        const fnFinal = Module.findExportByName(lib, "EVP_DecryptFinal_ex");
        if (fnFinal) {
            Interceptor.attach(fnFinal, {
                onEnter(args) { this.ctx = args[0].toString(); },
                onLeave(ret) {
                    if (ret.toInt32() !== 1) return;
                    const chunks = accumulator.get(this.ctx);
                    if (!chunks) return;
                    accumulator.delete(this.ctx);

                    // Concatenate all chunks
                    const total = chunks.reduce((s, c) => s + c.length, 0);
                    const full = new Uint8Array(total);
                    let off = 0;
                    for (const c of chunks) { full.set(c, off); off += c.length; }

                    sendBuf("EVP_Decrypt", "AES-native", full);
                }
            });
        }
        console.log("[+] EVP_DecryptUpdate hooked in " + lib);
        break;
    }
})();

// ── 4. Enumerate native modules (log to identify game's .so) ─────────────────
console.log("\n[*] Native modules containing 'decrypt' or 'niantic':");
Process.enumerateModules().forEach(m => {
    const n = m.name.toLowerCase();
    if (n.includes("niantic") || n.includes("pikmin") || n.includes("lightship") ||
        n.includes("vps") || n.includes("crypto") || n.includes("ssl")) {
        console.log("    " + m.name + "  base=" + m.base + "  size=" + m.size);
    }
});

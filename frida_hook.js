/**
 * frida_hook.js
 * Hook ALL libcrypto.so instances for EVP_Decrypt* (BoringSSL).
 * libNianticLabsPlugin.so calls into one of the three libcrypto.so copies.
 */

"use strict";

const MIN_DUMP_SIZE = 50000;   // rpc2 payload is ~315KB
let dumpIndex = 0;

function hexOf(arr, n) {
    n = Math.min(n || 32, arr.length);
    let s = "";
    for (let i = 0; i < n; i++) s += ("0" + (arr[i] & 0xff).toString(16)).slice(-2) + " ";
    return s.trimEnd();
}

function sendBuf(label, alg, bytes) {
    if (bytes.length < MIN_DUMP_SIZE) return;
    const idx = dumpIndex++;
    console.log("\n[CAPTURED] " + label + "  alg=" + alg + "  len=" + bytes.length);
    console.log("  preview: " + hexOf(bytes, 32));
    if (bytes.length >= 4) {
        const u32 = bytes[0] | (bytes[1]<<8) | (bytes[2]<<16) | (bytes[3]<<24);
        if (u32 > 0 && u32 < 500) console.log("  ** FlatBuffers root_off=" + u32);
    }
    send({ type: "buffer", index: idx, label: label, alg: alg, len: bytes.length },
         bytes.buffer || bytes);
}

// ── Hook all instances of libcrypto.so ────────────────────────────────────────
const accumulator = new Map();  // ctx_addr → Uint8Array[]

function hookCryptoModule(mod) {
    let foundUpdate = false, foundFinal = false;

    mod.enumerateExports().forEach(exp => {
        if (exp.name === "EVP_DecryptUpdate") {
            foundUpdate = true;
            Interceptor.attach(exp.address, {
                onEnter(args) {
                    this.ctx    = args[0].toString();
                    this.outPtr = args[1];
                    this.lenPtr = args[2];
                },
                onLeave(ret) {
                    if (ret.toInt32() !== 1) return;
                    try {
                        const written = this.lenPtr.readS32();
                        if (written <= 0 || written > 50 * 1024 * 1024) return;
                        const chunk = new Uint8Array(this.outPtr.readByteArray(written));
                        if (!accumulator.has(this.ctx)) accumulator.set(this.ctx, []);
                        accumulator.get(this.ctx).push(chunk);
                        if (written > 10000) {
                            console.log("[EVP_DecryptUpdate] " + mod.name +
                                        "@" + mod.base + "  ctx=..." +
                                        this.ctx.slice(-6) + "  written=" + written +
                                        "  preview: " + hexOf(chunk, 24));
                        }
                    } catch(_) {}
                }
            });
        }

        if (exp.name === "EVP_DecryptFinal_ex") {
            foundFinal = true;
            Interceptor.attach(exp.address, {
                onEnter(args) { this.ctx = args[0].toString(); },
                onLeave(ret) {
                    if (ret.toInt32() !== 1) return;
                    const chunks = accumulator.get(this.ctx);
                    accumulator.delete(this.ctx);
                    if (!chunks || chunks.length === 0) return;

                    const total = chunks.reduce((s, c) => s + c.length, 0);
                    const full  = new Uint8Array(total);
                    let off = 0;
                    for (const c of chunks) { full.set(c, off); off += c.length; }

                    console.log("[EVP_DecryptFinal_ex] " + mod.name +
                                "  total_plaintext=" + total);
                    sendBuf("EVP_Decrypt(" + mod.name + "@" + mod.base + ")",
                            "AES-GCM/native", full);
                }
            });
        }
    });

    console.log("[+] " + mod.name + "@" + mod.base +
                "  EVP_DecryptUpdate=" + foundUpdate +
                "  EVP_DecryptFinal_ex=" + foundFinal);
}

// Hook every libcrypto.so instance
const cryptoMods = Process.enumerateModules().filter(m => m.name === "libcrypto.so");
console.log("[*] Found " + cryptoMods.length + " libcrypto.so instance(s)");
cryptoMods.forEach(hookCryptoModule);

// ── Java Cipher (decrypt mode, >50KB, belt-and-suspenders) ───────────────────
Java.perform(function() {
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const DECRYPT_MODE = 2;

        function fromJava(jArr) {
            const arr = Java.array("byte", jArr);
            const out = new Uint8Array(arr.length);
            for (let i = 0; i < arr.length; i++) out[i] = arr[i] & 0xff;
            return out;
        }

        // Save original overloads and call them to avoid recursion issues
        const orig1 = Cipher.doFinal.overload("[B");
        const orig3 = Cipher.doFinal.overload("[B", "int", "int");

        orig1.implementation = function(input) {
            const result = orig1.call(this, input);
            // Capture all large outputs regardless of mode (decode_rpc2.py will check entropy)
            if (result && result.length >= MIN_DUMP_SIZE) {
                const alg = this.getAlgorithm ? this.getAlgorithm() : "?";
                sendBuf("Java.Cipher", alg, fromJava(result));
            }
            return result;
        };

        orig3.implementation = function(input, off, len) {
            const result = orig3.call(this, input, off, len);
            if (result && result.length >= MIN_DUMP_SIZE) {
                const alg = this.getAlgorithm ? this.getAlgorithm() : "?";
                sendBuf("Java.Cipher/3", alg, fromJava(result));
            }
            return result;
        };

        console.log("[+] Java Cipher.doFinal hooked (decrypt + >" + MIN_DUMP_SIZE + " bytes)");
    } catch(e) {
        console.log("[-] Java Cipher hook: " + e);
    }
});

// ── List libNianticLabsPlugin.so exports related to crypto ───────────────────
console.log("\n[*] libNianticLabsPlugin.so crypto-related exports:");
const nianticMod = Process.enumerateModules().find(m => m.name === "libNianticLabsPlugin.so");
if (nianticMod) {
    const interesting = nianticMod.enumerateExports().filter(e => {
        const n = e.name.toLowerCase();
        return n.includes("decrypt") || n.includes("cipher") || n.includes("aes") ||
               n.includes("crypto") || n.includes("rpc") || n.includes("proto");
    });
    if (interesting.length === 0) {
        console.log("  (no matching exports — likely stripped)");
    } else {
        interesting.slice(0, 30).forEach(e => console.log("  " + e.name + "  @" + e.address));
    }
} else {
    console.log("  libNianticLabsPlugin.so not found in module list");
}

console.log("\n[*] Waiting for rpc2 decryption (trigger: open game map)...");

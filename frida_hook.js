/**
 * frida_hook.js
 * Hook Pikmin Bloom's rpc2 response decryption.
 * Sends decrypted buffers back to run_frida.py via message channel.
 * Saved to ./decrypted_dumps/ on your Mac automatically.
 */

"use strict";

const MIN_DUMP_SIZE = 1000;
let dumpIndex = 0;

function hexpreview(arr, n) {
    n = Math.min(n || 32, arr.length);
    let s = "";
    for (let i = 0; i < n; i++) s += ("0" + (arr[i] & 0xff).toString(16)).slice(-2) + " ";
    return s.trimEnd();
}

function sendBuffer(label, alg, javaByteArray) {
    const idx = dumpIndex++;
    // Convert Java byte[] to JS ArrayBuffer
    const arr = Java.array("byte", javaByteArray);
    const buf = new Uint8Array(arr.length);
    for (let i = 0; i < arr.length; i++) buf[i] = arr[i] & 0xff;

    const preview = hexpreview(buf, 32);
    console.log("\n[" + label + "] alg=" + alg +
                "  len=" + buf.length + "  preview: " + preview);

    // Check for FlatBuffers root offset (small u32 at start)
    if (buf.length >= 4) {
        const u32 = buf[0] | (buf[1]<<8) | (buf[2]<<16) | (buf[3]<<24);
        if (u32 > 0 && u32 < 500) {
            console.log("  ** Looks like FlatBuffers! root_off=" + u32);
        }
    }

    // Send binary data to Python host (saved to disk there)
    send({ type: "buffer", index: idx, label: label, alg: alg, len: buf.length },
         buf.buffer);
}

Java.perform(function() {
    console.log("[*] frida_hook.js loaded — waiting for Cipher.doFinal()");

    // ── javax.crypto.Cipher.doFinal(byte[]) ──────────────────────────────────
    try {
        const Cipher = Java.use("javax.crypto.Cipher");

        Cipher.doFinal.overload("[B").implementation = function(input) {
            const result = this.doFinal(input);
            if (result && result.length >= MIN_DUMP_SIZE) {
                sendBuffer("Cipher.doFinal", this.getAlgorithm(), result);
            }
            return result;
        };

        Cipher.doFinal.overload("[B", "int", "int").implementation = function(input, off, len) {
            const result = this.doFinal(input, off, len);
            if (result && result.length >= MIN_DUMP_SIZE) {
                sendBuffer("Cipher.doFinal/3", this.getAlgorithm(), result);
            }
            return result;
        };

        console.log("[+] Cipher.doFinal hooked");
    } catch(e) {
        console.log("[-] Cipher hook failed: " + e);
    }

    // ── OkHttp3 ResponseBody.bytes() ─────────────────────────────────────────
    try {
        const ResponseBody = Java.use("okhttp3.ResponseBody");
        ResponseBody.bytes.implementation = function() {
            const result = this.bytes();
            if (result && result.length >= MIN_DUMP_SIZE) {
                sendBuffer("OkHttp.bytes", "raw-http", result);
            }
            return result;
        };
        console.log("[+] OkHttp ResponseBody.bytes hooked");
    } catch(e) {
        console.log("[-] OkHttp hook skipped: " + e);
    }
});

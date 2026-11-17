/* Bastion challenge client (src/sec/challenge.c embeds it; docs/challenge.md is the contract).
 * Bastion has set window.BASTION = { token, difficulty, verifyUrl, redirect } before this runs.
 * BASTION.solve() finds a nonce such that SHA-256(token + "." + nonce) starts with `difficulty`
 * zero bits, posts token, nonce and redirect to verifyUrl and lets the browser follow the
 * redirect that sets the pass cookie. The work runs in a Web Worker when one can start, else in
 * short slices on the page so it stays responsive. */
(function () {
	"use strict";
	var B = window.BASTION;
	if (!B) return;

	/* SHA-256 and the search, as source text: the same code runs in the worker. */
	var core = function () {
		var K = [
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		];
		var W = new Array(64);
		/* The digest of an ASCII string, as eight 32-bit words. */
		function sha256(s) {
			var n = s.length, words = ((n + 8) >> 6) + 1, m = new Array(words * 16), i;
			for (i = 0; i < m.length; i++) m[i] = 0;
			for (i = 0; i < n; i++) m[i >> 2] |= (s.charCodeAt(i) & 0xff) << (24 - (i & 3) * 8);
			m[n >> 2] |= 0x80 << (24 - (n & 3) * 8);
			m[words * 16 - 1] = n * 8;
			var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
				h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
			for (var b = 0; b < m.length; b += 16) {
				var a = h0, bb = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7, t;
				for (t = 0; t < 64; t++) {
					if (t < 16) W[t] = m[b + t] | 0;
					else {
						var x = W[t - 15], y = W[t - 2];
						var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
						var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
						W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
					}
					var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
					var ch = (e & f) ^ (~e & g);
					var t1 = (h + S1 + ch + K[t] + W[t]) | 0;
					var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
					var mj = (a & bb) ^ (a & c) ^ (bb & c);
					var t2 = (S0 + mj) | 0;
					h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
				}
				h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
				h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
			}
			return [h0, h1, h2, h3, h4, h5, h6, h7];
		}
		function zeroBits(h, bits) {
			for (var i = 0; bits > 0; i++, bits -= 32) {
				var w = h[i] >>> 0;
				if (bits >= 32) { if (w !== 0) return false; }
				else if ((w >>> (32 - bits)) !== 0) return false;
			}
			return true;
		}
		/* Tries `count` nonces from `from`; the nonce found, or -1. */
		function search(token, bits, from, count) {
			for (var n = from; n < from + count; n++)
				if (zeroBits(sha256(token + "." + n), bits)) return n;
			return -1;
		}
		return { sha256: sha256, zeroBits: zeroBits, search: search };
	};

	function submit(nonce) {
		var f = document.createElement("form");
		f.method = "POST";
		f.action = B.verifyUrl;
		var add = function (k, v) {
			var i = document.createElement("input");
			i.type = "hidden"; i.name = k; i.value = String(v);
			f.appendChild(i);
		};
		add("token", B.token);
		add("nonce", nonce);
		add("redirect", B.redirect);
		(document.body || document.documentElement).appendChild(f);
		f.submit();
	}

	function onPage(resolve) {
		var c = core(), from = 0, slice = 2000;
		(function step() {
			var n = c.search(B.token, B.difficulty, from, slice);
			if (n >= 0) { resolve(n); return; }
			from += slice;
			setTimeout(step, 0);
		})();
	}

	function inWorker(resolve, fallback) {
		var src = "var c=(" + core.toString() + ")();onmessage=function(e){var d=e.data,f=0;" +
			"for(;;){var n=c.search(d.token,d.difficulty,f,50000);if(n>=0){postMessage(n);return;}f+=50000;}};";
		var w;
		try {
			w = new Worker(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
		} catch (e) {
			fallback();
			return;
		}
		w.onmessage = function (e) { w.terminate(); resolve(e.data); };
		w.onerror = function () { w.terminate(); fallback(); };
		w.postMessage({ token: B.token, difficulty: B.difficulty });
	}

	B.sha256 = core().sha256;
	B.zeroBits = core().zeroBits;
	B.solve = function () {
		return new Promise(function (resolve) {
			var done = function (n) { submit(n); resolve(n); };
			if (typeof Worker === "function" && typeof Blob === "function" && window.URL)
				inWorker(done, function () { onPage(done); });
			else
				onPage(done);
		});
	};

	var start = function () { if (document.getElementById("bastion-autostart")) B.solve(); };
	if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
	else start();
})();

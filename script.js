/* =========================================================
   CipherX – Text Encryption and Decryption System
   Logic for Caesar, Vigenère and XOR ciphers + UI wiring.

   NOTE: These are classical, educational ciphers. They are
   NOT secure and must not be used for real-world secrecy.
   ========================================================= */

"use strict";

/* =========================================================
   1. Caesar Cipher
   ---------------------------------------------------------
   Shifts every letter by a fixed number of positions.
   Non-letter characters (spaces, digits, punctuation) pass
   through unchanged. Uppercase and lowercase are preserved.
   ========================================================= */
const CaesarCipher = {
  /**
   * Shift every letter of `text` by `shift` positions.
   * Negative shifts are supported (used for decryption).
   */
  shiftText(text, shift) {
    // Normalise any integer shift into the 0–25 range.
    const s = ((shift % 26) + 26) % 26;
    let result = "";

    for (const ch of text) {
      const code = ch.charCodeAt(0);

      if (code >= 65 && code <= 90) {
        // Uppercase A–Z
        result += String.fromCharCode(((code - 65 + s) % 26) + 65);
      } else if (code >= 97 && code <= 122) {
        // Lowercase a–z
        result += String.fromCharCode(((code - 97 + s) % 26) + 97);
      } else {
        // Everything else stays the same.
        result += ch;
      }
    }
    return result;
  },

  encrypt(text, key) { return this.shiftText(text, this.parseKey(key)); },
  decrypt(text, key) { return this.shiftText(text, -this.parseKey(key)); },

  /** Validate + convert the key string into an integer shift. */
  parseKey(key) {
    const trimmed = String(key).trim();
    if (trimmed === "") {
      throw new Error("Caesar cipher needs a shift key. Try a number like 3.");
    }
    if (!/^-?\d+$/.test(trimmed)) {
      throw new Error("Caesar shift key must be a whole number (e.g. 3 or -5).");
    }
    return parseInt(trimmed, 10);
  }
};

/* =========================================================
   2. Vigenère Cipher
   ---------------------------------------------------------
   A keyword provides a moving shift: A=0, B=1, … Z=25.
   The keyword repeats and only advances on letters, so
   spaces and punctuation do not consume keyword letters.
   ========================================================= */
const VigenereCipher = {
  /**
   * @param {string} text
   * @param {string} keyword
   * @param {"encrypt"|"decrypt"} mode
   */
  transform(text, keyword, mode) {
    const key = VigenereCipher.parseKey(keyword); // uppercase A–Z only
    let result = "";
    let keyIndex = 0;

    for (const ch of text) {
      const code = ch.charCodeAt(0);
      const isUpper = code >= 65 && code <= 90;
      const isLower = code >= 97 && code <= 122;

      if (isUpper || isLower) {
        const base = isUpper ? 65 : 97;
        const kShift = key.charCodeAt(keyIndex % key.length) - 65;
        const shift = mode === "encrypt" ? kShift : (26 - kShift) % 26;

        result += String.fromCharCode(((code - base + shift) % 26) + base);
        keyIndex++; // keyword advances only when we encrypt/decrypt a letter
      } else {
        result += ch; // preserve spaces & punctuation
      }
    }
    return result;
  },

  encrypt(text, key) { return this.transform(text, key, "encrypt"); },
  decrypt(text, key) { return this.transform(text, key, "decrypt"); },

  /** Validate the keyword and return it uppercased. */
  parseKey(key) {
    const trimmed = String(key).trim();
    if (trimmed === "") {
      throw new Error("Vigenère cipher needs a keyword. Try a word like LEMON.");
    }
    if (!/^[A-Za-z]+$/.test(trimmed)) {
      throw new Error("Vigenère keyword may only contain letters (A–Z).");
    }
    return trimmed.toUpperCase();
  }
};

/* =========================================================
   3. XOR Cipher
   ---------------------------------------------------------
   Converts text to UTF-8 bytes and XORs each byte with the
   repeating key bytes. Encryption output is hexadecimal so
   the binary result is readable. Decryption parses that hex
   and reverses the operation.
   ========================================================= */
const XorCipher = {
  encoder: new TextEncoder(),
  decoder: new TextDecoder(),

  encrypt(text, key) {
    const keyBytes = XorCipher.keyBytes(key);
    const dataBytes = XorCipher.encoder.encode(text);
    const out = XorCipher.xor(dataBytes, keyBytes);
    return XorCipher.toHex(out);
  },

  decrypt(hexText, key) {
    const keyBytes = XorCipher.keyBytes(key);
    const dataBytes = XorCipher.fromHex(hexText);
    const out = XorCipher.xor(dataBytes, keyBytes);
    // decode() may throw on invalid UTF-8 sequences.
    return XorCipher.decoder.decode(out);
  },

  /** Validate the key and return its UTF-8 bytes. */
  keyBytes(key) {
    if (String(key) === "") {
      throw new Error("XOR cipher needs a non-empty key.");
    }
    return XorCipher.encoder.encode(String(key));
  },

  /** XOR two byte arrays, repeating the key as needed. */
  xor(data, key) {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      out[i] = data[i] ^ key[i % key.length];
    }
    return out;
  },

  /** Convert bytes to an uppercase, space-separated hex string. */
  toHex(bytes) {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .toUpperCase();
  },

  /** Parse a hex string (spaces allowed) back into bytes. */
  fromHex(hexText) {
    const clean = String(hexText).replace(/\s+/g, "");
    if (clean.length === 0) {
      throw new Error("Enter the hexadecimal ciphertext produced by encryption.");
    }
    if (clean.length % 2 !== 0) {
      throw new Error("Invalid hex: ciphertext must have an even number of hex digits.");
    }
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error("Invalid hex: only characters 0–9 and A–F are allowed.");
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
};

/* =========================================================
   4. UI wiring
   ---------------------------------------------------------
   Reusable metadata drives both the algorithm cards and the
   workspace, so adding a cipher is a small, local change.
   ========================================================= */
(function initApp() {
  // ---- Per-algorithm configuration (single source of truth) ----
  const ALGORITHMS = {
    caesar: {
      name: "Caesar Cipher",
      badge: "Shift-based encryption",
      keyLabel: "Shift key",
      keyPlaceholder: "e.g. 3",
      keyHint: "whole number, e.g. 3",
      run: (text, key, mode) =>
        mode === "encrypt" ? CaesarCipher.encrypt(text, key) : CaesarCipher.decrypt(text, key)
    },
    vigenere: {
      name: "Vigenère Cipher",
      badge: "Keyword-based encryption",
      keyLabel: "Keyword",
      keyPlaceholder: "e.g. LEMON",
      keyHint: "letters only, e.g. LEMON",
      run: (text, key, mode) =>
        mode === "encrypt" ? VigenereCipher.encrypt(text, key) : VigenereCipher.decrypt(text, key)
    },
    xor: {
      name: "XOR Cipher",
      badge: "Bitwise encryption",
      keyLabel: "XOR key",
      keyPlaceholder: "e.g. secret",
      keyHint: "any text, e.g. secret",
      run: (text, key, mode) =>
        mode === "encrypt" ? XorCipher.encrypt(text, key) : XorCipher.decrypt(text, key)
    }
  };

  // ---- Cache DOM elements ----
  const els = {
    cards: Array.from(document.querySelectorAll(".algo-card")),
    navLinks: Array.from(document.querySelectorAll(".nav-link")),
    wsTitle: document.getElementById("wsTitle"),
    wsBadge: document.getElementById("wsBadge"),
    keyLabel: document.getElementById("keyLabel"),
    keyHint: document.getElementById("keyHint"),
    key: document.getElementById("key"),
    input: document.getElementById("input"),
    output: document.getElementById("output"),
    outputLabel: document.getElementById("outputLabel"),
    charCount: document.getElementById("charCount"),
    encryptBtn: document.getElementById("encryptBtn"),
    decryptBtn: document.getElementById("decryptBtn"),
    clearBtn: document.getElementById("clearBtn"),
    copyBtn: document.getElementById("copyBtn"),
    swapBtn: document.getElementById("swapBtn"),
    exportBtn: document.getElementById("exportNavBtn"),
    toasts: document.getElementById("toasts")
  };

  // Currently selected algorithm key (defaults to Caesar).
  let currentAlgo = "caesar";

  /* ---------- Toast notifications ---------- */
  function toast(message, type) {
    if (!els.toasts) return;
    const el = document.createElement("div");
    el.className = "toast " + (type || "success");
    el.textContent = message;
    els.toasts.appendChild(el);
    // Auto-dismiss after a short delay.
    setTimeout(() => {
      el.classList.add("hide");
      setTimeout(() => el.remove(), 300);
    }, 3200);
  }

  /* ---------- Character counter ---------- */
  function updateCounter() {
    els.charCount.textContent = els.input.value.length;
  }

  /* ---------- Algorithm selection ---------- */
  function selectAlgorithm(algo) {
    if (!ALGORITHMS[algo]) return;
    currentAlgo = algo;
    const cfg = ALGORITHMS[algo];

    // Highlight the matching card.
    els.cards.forEach((card) => {
      const active = card.dataset.algo === algo;
      card.classList.toggle("is-active", active);
      card.setAttribute("aria-pressed", String(active));
    });

    // Update the workspace header + dynamic key field.
    els.wsTitle.textContent = cfg.name;
    els.wsBadge.textContent = cfg.badge;
    els.keyLabel.textContent = cfg.keyLabel;
    els.key.placeholder = cfg.keyPlaceholder;
    els.keyHint.textContent = cfg.keyHint;
    els.outputLabel.textContent = "—";
  }

  /* ---------- Run encrypt / decrypt ---------- */
  function run(mode) {
    const text = els.input.value;

    if (text === "") {
      els.output.value = "";
      els.outputLabel.textContent = "—";
      toast("Please enter some input text first.", "error");
      return;
    }

    try {
      const result = ALGORITHMS[currentAlgo].run(text, els.key.value, mode);
      els.output.value = result;
      els.outputLabel.textContent =
        ALGORITHMS[currentAlgo].name + " · " + (mode === "encrypt" ? "Encrypted" : "Decrypted");

      if (mode === "decrypt" && result === "") {
        toast("No readable text found. Check the key and the ciphertext.", "error");
      } else {
        toast((mode === "encrypt" ? "Encryption" : "Decryption") + " successful.", "success");
      }
    } catch (err) {
      // Any validation / parsing error is surfaced to the user.
      els.output.value = "";
      els.outputLabel.textContent = "—";
      toast(err.message, "error");
    }
  }

  /* ---------- Copy output to clipboard ---------- */
  async function copyOutput() {
    const text = els.output.value;
    if (text === "") {
      toast("Nothing to copy — the output is empty.", "error");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      toast("Output copied to clipboard.", "success");
    } catch (e) {
      // Fallback for browsers / contexts without the Clipboard API.
      els.output.select();
      document.execCommand("copy");
      toast("Output copied to clipboard.", "success");
    }
  }

  /* ---------- Clear inputs and output ---------- */
  function clearAll() {
    els.input.value = "";
    els.output.value = "";
    els.outputLabel.textContent = "—";
    updateCounter();
    toast("Cleared.", "success");
    els.input.focus();
  }

  /* ---------- Move output back into the input ---------- */
  function useOutputAsInput() {
    if (els.output.value === "") {
      toast("Nothing to move — the output is empty.", "error");
      return;
    }
    els.input.value = els.output.value;
    els.output.value = "";
    els.outputLabel.textContent = "—";
    updateCounter();
    toast("Output moved to the input.", "success");
  }

  /* ---------- Export the current output as a .txt file ---------- */
  function exportOutput() {
    const text = els.output.value;
    if (text === "") {
      toast("Nothing to export — the output is empty.", "error");
      return;
    }
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cipherx-" + currentAlgo + "-output.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast("Output exported as a text file.", "success");
  }

  /* ---------- Scroll-spy: highlight the active nav link ---------- */
  function initScrollSpy() {
    if (!("IntersectionObserver" in window)) return;
    const targets = els.navLinks
      .map((link) => document.querySelector(link.getAttribute("href")))
      .filter(Boolean);

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          els.navLinks.forEach((link) =>
            link.classList.toggle("is-active", link.getAttribute("href") === "#" + entry.target.id)
          );
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    targets.forEach((t) => observer.observe(t));
  }

  // ---- Event listeners ----
  // Clicking a card (or its Explore button) selects it; Explore also jumps to the workspace.
  els.cards.forEach((card) => {
    const exploreBtn = card.querySelector(".btn-explore");

    card.addEventListener("click", () => selectAlgorithm(card.dataset.algo));
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectAlgorithm(card.dataset.algo);
      }
    });
    if (exploreBtn) {
      exploreBtn.addEventListener("click", (e) => {
        e.stopPropagation(); // avoid double-handling with the card click
        selectAlgorithm(card.dataset.algo);
        document.getElementById("workspace").scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  });

  els.encryptBtn.addEventListener("click", () => run("encrypt"));
  els.decryptBtn.addEventListener("click", () => run("decrypt"));
  els.clearBtn.addEventListener("click", clearAll);
  els.copyBtn.addEventListener("click", copyOutput);
  els.swapBtn.addEventListener("click", useOutputAsInput);
  els.exportBtn.addEventListener("click", exportOutput);
  els.input.addEventListener("input", updateCounter);

  // ---- Initialise ----
  selectAlgorithm(currentAlgo);
  updateCounter();
  initScrollSpy();
})();

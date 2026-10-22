// CBOR, base64url and HPKE (RFC 9180, base mode, receiver side) for the
// test verifier. Plain script: attaches to globalThis.VCu so the page and a
// Node test can both load it.
(function (root) {
  "use strict";

  // --- base64url / hex ------------------------------------------------------

  const b64url = (bytes) =>
    btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let i = 0;
    for (const p of parts) { out.set(p, i); i += p.length; }
    return out;
  };
  const utf8 = (s) => new TextEncoder().encode(s);

  // --- CBOR encode (definite lengths) ----------------------------------------

  class Tag { constructor(tag, value) { this.tag = tag; this.value = value; } }

  function cborEncode(value) {
    const out = [];
    const head = (major, n) => {
      if (n < 24) out.push((major << 5) | n);
      else if (n < 0x100) out.push((major << 5) | 24, n);
      else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
      else out.push((major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
    };
    const enc = (v) => {
      if (v === null) out.push(0xf6);
      else if (v === false) out.push(0xf4);
      else if (v === true) out.push(0xf5);
      else if (typeof v === "number") {
        if (!Number.isInteger(v)) throw new Error("floats not supported");
        v >= 0 ? head(0, v) : head(1, -1 - v);
      } else if (typeof v === "string") { const b = utf8(v); head(3, b.length); out.push(...b); }
      else if (v instanceof Uint8Array) { head(2, v.length); out.push(...v); }
      else if (v instanceof Tag) { head(6, v.tag); enc(v.value); }
      else if (Array.isArray(v)) { head(4, v.length); v.forEach(enc); }
      else if (v instanceof Map) { head(5, v.size); for (const [k, x] of v) { enc(k); enc(x); } }
      else if (typeof v === "object") { const e = Object.entries(v); head(5, e.length); for (const [k, x] of e) { enc(k); enc(x); } }
      else throw new Error("unsupported CBOR type: " + typeof v);
    };
    enc(value);
    return new Uint8Array(out);
  }

  // --- CBOR decode -----------------------------------------------------------
  // Maps decode to Map (keys may be ints); tag 24 keeps its raw bytes.

  function cborDecode(bytes) {
    let i = 0;
    const len = (info) => {
      if (info < 24) return info;
      const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
      if (!n) throw new Error("indefinite lengths not supported");
      let v = 0;
      for (let k = 0; k < n; k++) v = v * 256 + bytes[i++];
      return v;
    };
    const item = () => {
      const b = bytes[i++], major = b >> 5, info = b & 31;
      switch (major) {
        case 0: return len(info);
        case 1: return -1 - len(info);
        case 2: { const n = len(info); const v = bytes.slice(i, i + n); i += n; return v; }
        case 3: { const n = len(info); const v = new TextDecoder().decode(bytes.slice(i, i + n)); i += n; return v; }
        case 4: { const n = len(info); return Array.from({ length: n }, item); }
        case 5: { const n = len(info); const m = new Map(); for (let k = 0; k < n; k++) { const key = item(); m.set(key, item()); } return m; }
        case 6: { const t = len(info); return new Tag(t, item()); }
        case 7:
          if (info === 20) return false;
          if (info === 21) return true;
          if (info === 22 || info === 23) return null;
          throw new Error("unsupported simple/float value");
      }
    };
    const v = item();
    if (i !== bytes.length) throw new Error("trailing bytes after CBOR item");
    return v;
  }

  // --- HPKE base mode open: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM

  const I2OSP = (n, w) => Uint8Array.from({ length: w }, (_, k) => (n >> (8 * (w - 1 - k))) & 0xff);
  const SUITE_KEM = concat(utf8("KEM"), I2OSP(0x0010, 2));
  const SUITE = concat(utf8("HPKE"), I2OSP(0x0010, 2), I2OSP(0x0001, 2), I2OSP(0x0001, 2));

  async function hmac(key, data) {
    const k = await crypto.subtle.importKey("raw", key.length ? key : new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
  }
  // HKDF-Extract with an empty salt = HMAC keyed with HashLen zero bytes.
  const labeledExtract = (salt, label, ikm, suite) => hmac(salt, concat(utf8("HPKE-v1"), suite, utf8(label), ikm));
  async function labeledExpand(prk, label, info, L, suite) {
    // L <= 32 here, so one HKDF-Expand block suffices.
    const t = await hmac(prk, concat(I2OSP(L, 2), utf8("HPKE-v1"), suite, utf8(label), info, Uint8Array.of(1)));
    return t.slice(0, L);
  }

  /** @param recipientKey ECDH P-256 CryptoKeyPair. */
  async function hpkeOpen(recipientKey, enc, cipherText, info) {
    const pkE = await crypto.subtle.importKey("raw", enc, { name: "ECDH", namedCurve: "P-256" }, false, []);
    const dh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pkE }, recipientKey.privateKey, 256));
    const pkRm = new Uint8Array(await crypto.subtle.exportKey("raw", recipientKey.publicKey));
    const eaePrk = await labeledExtract(new Uint8Array(0), "eae_prk", dh, SUITE_KEM);
    const sharedSecret = await labeledExpand(eaePrk, "shared_secret", concat(enc, pkRm), 32, SUITE_KEM);

    const pskIdHash = await labeledExtract(new Uint8Array(0), "psk_id_hash", new Uint8Array(0), SUITE);
    const infoHash = await labeledExtract(new Uint8Array(0), "info_hash", info, SUITE);
    const context = concat(Uint8Array.of(0), pskIdHash, infoHash); // mode_base
    const secret = await labeledExtract(sharedSecret, "secret", new Uint8Array(0), SUITE);
    const key = await labeledExpand(secret, "key", context, 16, SUITE);
    const nonce = await labeledExpand(secret, "base_nonce", context, 12, SUITE); // seq 0

    const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: new Uint8Array(0) }, aes, cipherText));
  }

  // --- Annex C -----------------------------------------------------------------

  /** SessionTranscript = [null, null, ["dcapi", SHA-256(CBOR([encryptionInfo, origin]))]] */
  async function sessionTranscript(encryptionInfoB64, origin) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", cborEncode([encryptionInfoB64, origin])));
    return [null, null, ["dcapi", digest]];
  }

  /** EncryptedResponse bytes -> decoded DeviceResponse. */
  async function openResponse(recipientKey, encryptedResponse, encryptionInfoB64, origin) {
    const envelope = cborDecode(encryptedResponse);
    if (!Array.isArray(envelope) || envelope[0] !== "dcapi") throw new Error('response is not ["dcapi", {...}]');
    const info = cborEncode(await sessionTranscript(encryptionInfoB64, origin));
    const plain = await hpkeOpen(recipientKey, envelope[1].get("enc"), envelope[1].get("cipherText"), info);
    return cborDecode(plain);
  }

  // --- Verification (issuer signature, digests, device signature) ------------
  // Debug-grade: the Document Signer certificate is NOT chain-validated here.

  /** SubjectPublicKeyInfo DER of an X.509 certificate (minimal DER walk). */
  function spkiFromCertificate(der) {
    let i = 0;
    const header = () => {
      const tag = der[i++]; let len = der[i++];
      if (len & 0x80) { const n = len & 0x7f; len = 0; for (let k = 0; k < n; k++) len = len * 256 + der[i++]; }
      return { tag, len, start: i };
    };
    header();                       // Certificate SEQUENCE
    const tbs = header();           // TBSCertificate SEQUENCE
    const skip = () => { const h = header(); i = h.start + h.len; };
    if (der[i] === 0xa0) skip();    // [0] version
    skip(); skip(); skip(); skip(); skip(); // serial, signature alg, issuer, validity, subject
    const spki = header();
    return der.slice(spki.start - (spki.len > 127 ? (spki.len > 255 ? 4 : 3) : 2), spki.start + spki.len);
  }

  async function ecdsaVerify(publicKey, signature, data) {
    const hash = { 32: "SHA-256", 48: "SHA-384", 66: "SHA-512" }[signature.length / 2];
    return crypto.subtle.verify({ name: "ECDSA", hash }, publicKey, signature, data);
  }

  const sigStructure = (protectedBytes, payload) => cborEncode(["Signature1", protectedBytes, new Uint8Array(0), payload]);

  /** Checks one document of a decrypted DeviceResponse. Returns {issuerSignature, digests, deviceSignature}. */
  async function verifyDocument(doc, transcript, deviceKeyOverride) {
    const issuerSigned = doc.get("issuerSigned");
    const [prot, unprot, payload, sig] = issuerSigned.get("issuerAuth");
    let x5 = unprot.get(33); x5 = x5 instanceof Uint8Array ? x5 : x5[0];
    const curve = { 64: "P-256", 96: "P-384", 132: "P-521" }[sig.length];
    const dsKey = await crypto.subtle.importKey("spki", spkiFromCertificate(x5), { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
    const issuerSignature = await ecdsaVerify(dsKey, sig, sigStructure(prot, payload));

    const mso = cborDecode(cborDecode(payload).value);
    const hashName = { "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512" }[mso.get("digestAlgorithm")];
    let digests = true;
    for (const [ns, items] of issuerSigned.get("nameSpaces")) {
      for (const item of items) {
        const e = cborDecode(item.value);
        const actual = new Uint8Array(await crypto.subtle.digest(hashName, cborEncode(item)));
        const expected = mso.get("valueDigests").get(ns)?.get(e.get("digestID"));
        if (!expected || hex(actual) !== hex(expected)) digests = false;
      }
    }

    // DeviceAuthentication over the session transcript, with the device key
    // the issuer bound into the MSO (or an override, for tests).
    const deviceSigned = doc.get("deviceSigned");
    const [dprot, , , dsig] = deviceSigned.get("deviceAuth").get("deviceSignature");
    const coseKey = mso.get("deviceKeyInfo").get("deviceKey");
    const jwk = deviceKeyOverride ?? { kty: "EC", crv: "P-256", x: b64url(coseKey.get(-2)), y: b64url(coseKey.get(-3)) };
    const deviceKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const deviceAuthentication = ["DeviceAuthentication", transcript, doc.get("docType"), deviceSigned.get("nameSpaces")];
    const detached = cborEncode(new Tag(24, cborEncode(deviceAuthentication)));
    const deviceSignature = await ecdsaVerify(deviceKey, dsig, sigStructure(dprot, detached));

    return { issuerSignature, digests, deviceSignature, validUntil: mso.get("validityInfo")?.get("validUntil") };
  }

  root.VCu = { Tag, cborEncode, cborDecode, b64url, fromB64url, hex, hpkeOpen, sessionTranscript, openResponse, verifyDocument };
})(globalThis);

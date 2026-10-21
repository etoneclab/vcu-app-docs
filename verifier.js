// Minimal ISO 18013-7 Annex C ("org-iso-mdoc") request builder for testing the
// VCu Wallet document provider extension from Safari 26+. Request side only:
// the HPKE-encrypted response is logged raw, and the ephemeral private key is
// kept in memory (`state.recipientKey`) for a later decrypting version.

"use strict";

// --- Minimal CBOR encoder (definite lengths only) --------------------------

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
    } else if (typeof v === "string") {
      const b = new TextEncoder().encode(v); head(3, b.length); out.push(...b);
    } else if (v instanceof Uint8Array) {
      head(2, v.length); out.push(...v);
    } else if (v instanceof Tag) {
      head(6, v.tag); enc(v.value);
    } else if (Array.isArray(v)) {
      head(4, v.length); v.forEach(enc);
    } else if (v instanceof Map) {
      head(5, v.size); for (const [k, x] of v) { enc(k); enc(x); }
    } else if (typeof v === "object") {
      const entries = Object.entries(v); head(5, entries.length);
      for (const [k, x] of entries) { enc(k); enc(x); }
    } else throw new Error("unsupported CBOR type: " + typeof v);
  };
  enc(value);
  return new Uint8Array(out);
}

// Tag 24: embedded CBOR data item, used for ItemsRequestBytes.
const embedded = (v) => new Tag(24, cborEncode(v));

// --- Helpers ---------------------------------------------------------------

const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => {
  const clean = s.replace(/[\s:]/g, "");
  if (!/^([0-9a-fA-F]{2})+$/.test(clean)) throw new Error("issuer AKI is not valid hex");
  return new Uint8Array(clean.match(/../g).map((h) => parseInt(h, 16)));
};

const logEl = document.getElementById("log");
const log = (msg) => { logEl.textContent += "\n" + msg; };
const state = {};

// --- Request construction --------------------------------------------------

async function buildRequest(elements, akiHex) {
  // Ephemeral reader key: its public half goes into EncryptionInfo so the
  // wallet can HPKE-encrypt the response to us.
  state.recipientKey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const jwk = await crypto.subtle.exportKey("jwk", state.recipientKey.publicKey);
  const coord = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

  // COSE_Key: kty EC2 (1:2), crv P-256 (-1:1), x (-2), y (-3).
  const coseKey = new Map([[1, 2], [-1, 1], [-2, coord(jwk.x)], [-3, coord(jwk.y)]]);
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const encryptionInfo = ["dcapi", { nonce, recipientPublicKey: coseKey }];

  const nameSpace = {};
  for (const el of elements) nameSpace[el] = false; // false = intentToRetain: no
  const itemsRequest = { docType: "org.iso.18013.5.1.mDL", nameSpaces: { "org.iso.18013.5.1": nameSpace } };
  if (akiHex) itemsRequest.requestInfo = { issuerIdentifiers: [fromHex(akiHex)] };

  const deviceRequest = { version: "1.0", docRequests: [{ itemsRequest: embedded(itemsRequest) }] };

  return {
    protocol: "org-iso-mdoc",
    data: {
      deviceRequest: b64url(cborEncode(deviceRequest)),
      encryptionInfo: b64url(cborEncode(encryptionInfo)),
    },
  };
}

// --- Environment check -----------------------------------------------------

function describeEnvironment() {
  const env = document.getElementById("env");
  const hasApi = typeof window.DigitalCredential !== "undefined";
  let protocolOk = "unknown";
  if (hasApi && typeof DigitalCredential.userAgentAllowsProtocol === "function") {
    protocolOk = DigitalCredential.userAgentAllowsProtocol("org-iso-mdoc") ? "yes" : "no";
  }
  env.innerHTML =
    `Secure context: <b class="${isSecureContext ? "ok" : "err"}">${isSecureContext}</b> · ` +
    `DigitalCredential API: <b class="${hasApi ? "ok" : "err"}">${hasApi}</b> · ` +
    `org-iso-mdoc allowed: <b>${protocolOk}</b>`;
}

// --- Main ------------------------------------------------------------------

document.getElementById("go").addEventListener("click", async (ev) => {
  const button = ev.currentTarget;
  const elements = [...document.querySelectorAll("input[name=el]:checked")].map((i) => i.value);
  const akiHex = document.getElementById("aki").value.trim();
  logEl.textContent = `[${new Date().toISOString()}] origin ${location.origin}`;

  let request;
  try {
    request = await buildRequest(elements, akiHex);
  } catch (e) {
    log("Failed to build request: " + e.message);
    return;
  }
  log("Request:\n" + JSON.stringify(request, null, 2));
  log("deviceRequest CBOR hex (paste into cbor.me):\n" +
      hex(Uint8Array.from(atob(request.data.deviceRequest.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));

  button.disabled = true;
  try {
    // Must run inside the click handler: the API requires transient user activation.
    const credential = await navigator.credentials.get({
      mediation: "required",
      digital: { requests: [request] },
    });
    log("Credential returned. protocol=" + credential.protocol);
    log("Raw data (HPKE-encrypted, not decrypted in this version):\n" + JSON.stringify(credential.data, null, 2));
  } catch (e) {
    // NotAllowedError: user cancelled or no matching provider; AbortError: timeout/cancel.
    log(`Error: ${e.name}: ${e.message}`);
  } finally {
    button.disabled = false;
  }
});

describeEnvironment();

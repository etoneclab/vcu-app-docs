// ISO 18013-7 Annex C ("org-iso-mdoc") test verifier for the VCu iOS
// wallet. Builds the request, calls the Digital Credentials API, then
// HPKE-decrypts the response with the ephemeral key kept in memory and shows
// the disclosed elements with issuer-signature, digest and device-signature
// checks. The Document Signer certificate is NOT chain-validated against an
// IACA — this is a debugging tool, not a verifier anyone should trust.

"use strict";

const { Tag, cborEncode, cborDecode, b64url, fromB64url, hex, openResponse, sessionTranscript, verifyDocument } = globalThis.VCu;

const logEl = document.getElementById("log");
const resultEl = document.getElementById("result");
const log = (msg) => { logEl.textContent += "\n" + msg; };
const state = {};

// --- Request construction --------------------------------------------------

async function buildRequest(docType, namespace, elements, akiHex) {
  // Ephemeral reader key; the wallet HPKE-encrypts the response to it.
  state.recipientKey = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", state.recipientKey.publicKey));
  // COSE_Key: kty EC2 (1:2), crv P-256 (-1:1), x (-2), y (-3).
  const coseKey = new Map([[1, 2], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]]);
  const encryptionInfo = ["dcapi", { nonce: crypto.getRandomValues(new Uint8Array(16)), recipientPublicKey: coseKey }];

  const nameSpace = {};
  for (const el of elements) nameSpace[el] = false; // intentToRetain: no
  const itemsRequest = { docType, nameSpaces: { [namespace]: nameSpace } };
  if (akiHex) itemsRequest.requestInfo = { issuerIdentifiers: [fromHex(akiHex)] };
  const deviceRequest = { version: "1.0", docRequests: [{ itemsRequest: new Tag(24, cborEncode(itemsRequest)) }] };

  return {
    protocol: "org-iso-mdoc",
    data: { deviceRequest: b64url(cborEncode(deviceRequest)), encryptionInfo: b64url(cborEncode(encryptionInfo)) },
  };
}

function fromHex(s) {
  const clean = s.replace(/[\s:]/g, "");
  if (!/^([0-9a-fA-F]{2})+$/.test(clean)) throw new Error("issuer AKI is not valid hex");
  return new Uint8Array(clean.match(/../g).map((h) => parseInt(h, 16)));
}

// --- Response --------------------------------------------------------------

/** The response field's shape isn't pinned down for iOS yet; accept the
 *  Annex C `{response: base64url}` object, a bare base64url string, or bytes. */
function encryptedResponseBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") return fromB64url(data);
  if (data && typeof data.response === "string") return fromB64url(data.response);
  throw new Error("unrecognized response shape: " + JSON.stringify(data).slice(0, 200));
}

async function show(deviceResponse, transcript) {
  const rows = [];
  const mark = (ok) => (ok ? '<b class="ok">✓</b>' : '<b class="err">✗</b>');
  for (const doc of deviceResponse.get("documents") ?? []) {
    rows.push(`<h2>${escapeHtml(doc.get("docType"))}</h2>`);
    try {
      const v = await verifyDocument(doc, transcript);
      rows.push(`<p>${mark(v.issuerSignature)} issuer signature · ${mark(v.digests)} element digests · ${mark(v.deviceSignature)} device signature (bound to this session)</p>`);
    } catch (e) {
      rows.push(`<p class="err">Verification error: ${escapeHtml(e.message)}</p>`);
    }
    rows.push("<table>");
    for (const [ns, items] of doc.get("issuerSigned").get("nameSpaces")) {
      for (const item of items) {
        const e = cborDecode(item.value);
        const value = e.get("elementValue");
        const shown = value instanceof Uint8Array ? `<${value.length} bytes>` : value instanceof Tag ? `tag ${value.tag}: ${value.value}` : String(value);
        rows.push(`<tr><td>${escapeHtml(ns)}</td><td>${escapeHtml(e.get("elementIdentifier"))}</td><td>${escapeHtml(shown)}</td></tr>`);
      }
    }
    rows.push(`</table><p class="hint">Document Signer certificate not chain-validated against an IACA on this page.</p>`);
  }
  resultEl.innerHTML = rows.join("");
}

const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

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
  const namespace = document.getElementById("ns").value.trim();
  const elements = [...document.querySelectorAll("input[name=el]:checked")].map((i) => i.value);
  const akiHex = document.getElementById("aki").value.trim();
  logEl.textContent = `[${new Date().toISOString()}] origin ${location.origin}`;
  resultEl.innerHTML = "";

  let request;
  try {
    request = await buildRequest("org.iso.18013.5.1.mDL", namespace, elements, akiHex);
  } catch (e) {
    log("Failed to build request: " + e.message);
    return;
  }
  log("Request:\n" + JSON.stringify(request, null, 2));
  log("deviceRequest CBOR hex (paste into cbor.me):\n" + hex(fromB64url(request.data.deviceRequest)));

  button.disabled = true;
  try {
    // Must run inside the click handler: the API requires user activation.
    const credential = await navigator.credentials.get({ mediation: "required", digital: { requests: [request] } });
    log(`Credential returned. protocol=${credential.protocol}`);
    log("Raw data:\n" + JSON.stringify(credential.data, null, 2).slice(0, 2000));
    const deviceResponse = await openResponse(state.recipientKey, encryptedResponseBytes(credential.data),
                                              request.data.encryptionInfo, location.origin);
    log("Decrypted DeviceResponse, status " + deviceResponse.get("status"));
    await show(deviceResponse, await sessionTranscript(request.data.encryptionInfo, location.origin));
  } catch (e) {
    // NotAllowedError: user cancelled or no matching provider; AbortError: timeout/cancel.
    log(`Error: ${e.name}: ${e.message}`);
  } finally {
    button.disabled = false;
  }
});

// --- Platform-built requests (the platform holds the decryption key) -------

let platformResponse = null;
document.getElementById("goPlatform").addEventListener("click", async (ev) => {
  const button = ev.currentTarget;
  logEl.textContent = `[${new Date().toISOString()}] origin ${location.origin} (platform request)`;
  resultEl.innerHTML = "";
  let requests;
  try {
    requests = JSON.parse(document.getElementById("platformRequest").value.trim());
    if (!Array.isArray(requests)) throw new Error("expected the JSON array printed by the script");
  } catch (e) {
    log("Not a platform request: " + e.message);
    return;
  }
  button.disabled = true;
  try {
    const credential = await navigator.credentials.get({ mediation: "required", digital: { requests } });
    platformResponse = JSON.stringify({ protocol: credential.protocol, data: credential.data });
    log(`Credential returned. protocol=${credential.protocol}`);
    log("Response (encrypted to the platform):\n" + platformResponse.slice(0, 400) + "…");
    document.getElementById("copyResponse").style.display = "block";
  } catch (e) {
    log(`Error: ${e.name}: ${e.message}`);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("copyResponse").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(platformResponse);
    log("Response copied. On the Mac: pbpaste | node Scripts/sandbox-dcapi.mjs --forward");
  } catch (e) {
    log("Copy failed: " + e.message);
  }
});

describeEnvironment();

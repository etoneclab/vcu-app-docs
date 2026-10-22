# VCu DC API Test Verifier

Static GitHub Pages site for testing the VCu iOS wallet's Identity Document
Provider extension from Safari 26+. Sends an ISO 18013-7 Annex C
(`org-iso-mdoc`) mDL request via the W3C Digital Credentials API.

Decrypts the HPKE response in the browser (`lib.js`: CBOR, HPKE base mode
DHKEM(P-256)/HKDF-SHA256/AES-128-GCM, Annex C session transcript) and shows
the disclosed elements. Debugging tool only: no reader authentication, and
issuer and device signatures are not verified.

Served at https://etoneclab.github.io/vcu-app-docs/

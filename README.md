# VCu DC API Test Verifier

Static GitHub Pages site for testing the VCu iOS wallet's Identity Document
Provider extension from Safari 26+. Sends an ISO 18013-7 Annex C
(`org-iso-mdoc`) mDL request via the W3C Digital Credentials API.

Debugging tool only: no reader authentication, no issuer trust validation, and
the HPKE-encrypted response is shown raw, not decrypted.

Served at https://etoneclab.github.io/vcu-ios-app/

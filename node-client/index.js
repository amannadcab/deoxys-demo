import deoxysii from '@oasisprotocol/deoxysii';
import axios from 'axios';
import cbor from 'cbor';

const { AEAD, KeySize, NonceSize } = deoxysii;

async function main() {
  const key = new Uint8Array(KeySize).fill(1);       // 32-byte shared key
  const nonce = new Uint8Array(NonceSize).fill(2);   // 15-byte nonce
  const aad = new Uint8Array();                      // no associated data

  // === Your data to send ===
  const payload = {
    message: "Hello from Node.js Client",
    timestamp: Date.now(),
    sender: "client-node"
  };

  // === Encode with CBOR ===
  const message = cbor.encode(payload); // returns Uint8Array

  // === Encrypt with Deoxys-II ===
  const aead = new AEAD(key);
  const ciphertext = aead.encrypt(nonce, message, aad);

  // === Send encrypted + CBOR-wrapped payload ===
  const res = await axios.post("http://localhost:3000/exchange", {
    ciphertext: Buffer.from(ciphertext).toString("base64"),
    nonce: Buffer.from(nonce).toString("base64")
  });

  // === Handle response ===
  const { ciphertext: encResp, nonce: nonceResp } = res.data;
  const responseNonce = Buffer.from(nonceResp, "base64");
  const responseCiphertext = Buffer.from(encResp, "base64");

  // === Decrypt response ===
  const decrypted = aead.decrypt(responseNonce, responseCiphertext, aad);

  // === Decode CBOR ===
  const responsePayload = await cbor.decodeFirst(decrypted);
  console.log("✅ Server response (CBOR):", responsePayload);
}

main().catch(console.error);

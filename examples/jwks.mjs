import { CipherSuite } from "hpke";
import { algorithms } from "./algorithms.mjs";

import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, "jwks");
mkdirSync(outDir, { recursive: true });

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

// JWK Thumbprint (RFC 7638) — SHA-256 of the lexicographically sorted required members
function jwkThumbprint(jwk) {
  const input = JSON.stringify({ alg: jwk.alg, kty: jwk.kty, pub: jwk.pub });
  return createHash("sha256").update(input).digest("base64url");
}

const kty = "AKP";
for (const { alg, kem, kdf, aead } of algorithms) {
  const suite = new CipherSuite(kem, kdf, aead);
  const ikm = new Uint8Array(suite.KEM.Nsk);
  const algBytes = new TextEncoder().encode(alg);
  const ids = new Uint8Array(6);
  new DataView(ids.buffer).setUint16(0, suite.KEM.id);
  new DataView(ids.buffer).setUint16(2, suite.KDF.id);
  new DataView(ids.buffer).setUint16(4, suite.AEAD.id);
  const suffix = new Uint8Array(algBytes.length + ids.length);
  suffix.set(ids, 0);
  suffix.set(algBytes, ids.length);
  ikm.set(suffix, ikm.length - suffix.length);
  const keyPair = await suite.DeriveKeyPair(ikm, true);
  const pub = base64url(await suite.SerializePublicKey(keyPair.publicKey));
  const priv = base64url(await suite.SerializePrivateKey(keyPair.privateKey));
  const kid = jwkThumbprint({ kty, alg, pub });

  const jwk = {
    kty,
    alg,
    kid,
    pub,
    priv,
  };

  const filename = join(outDir, `${alg}.json`);
  writeFileSync(filename, JSON.stringify(jwk, null, 2) + "\n");
}

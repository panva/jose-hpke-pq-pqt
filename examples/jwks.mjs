import {
  CipherSuite,
  KEM_MLKEM768_P256,
  KEM_MLKEM768_X25519,
  KEM_MLKEM1024_P384,
  KEM_ML_KEM_768,
  KEM_ML_KEM_1024,
  KDF_SHAKE256,
  AEAD_AES_256_GCM,
  AEAD_ChaCha20Poly1305,
} from "hpke";

import { calculateJwkThumbprint } from "jose";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, "jwks");
mkdirSync(outDir, { recursive: true });

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

const algorithms = [
  // PQ/T Hybrid
  {
    alg: "HPKE-8",
    kem: KEM_MLKEM768_P256,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-8-KE",
    kem: KEM_MLKEM768_P256,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-9",
    kem: KEM_MLKEM768_P256,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-9-KE",
    kem: KEM_MLKEM768_P256,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-10",
    kem: KEM_MLKEM768_X25519,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-10-KE",
    kem: KEM_MLKEM768_X25519,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-11",
    kem: KEM_MLKEM768_X25519,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-11-KE",
    kem: KEM_MLKEM768_X25519,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-12",
    kem: KEM_MLKEM1024_P384,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-12-KE",
    kem: KEM_MLKEM1024_P384,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-13",
    kem: KEM_MLKEM1024_P384,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-13-KE",
    kem: KEM_MLKEM1024_P384,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  // Pure PQ
  {
    alg: "HPKE-14",
    kem: KEM_ML_KEM_768,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-14-KE",
    kem: KEM_ML_KEM_768,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-15",
    kem: KEM_ML_KEM_768,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-15-KE",
    kem: KEM_ML_KEM_768,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-16",
    kem: KEM_ML_KEM_1024,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-16-KE",
    kem: KEM_ML_KEM_1024,
    kdf: KDF_SHAKE256,
    aead: AEAD_AES_256_GCM,
  },
  {
    alg: "HPKE-17",
    kem: KEM_ML_KEM_1024,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
  {
    alg: "HPKE-17-KE",
    kem: KEM_ML_KEM_1024,
    kdf: KDF_SHAKE256,
    aead: AEAD_ChaCha20Poly1305,
  },
];

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
  const kid = await calculateJwkThumbprint({ kty, alg, pub });

  const jwk = {
    kty,
    alg,
    kid,
    pub,
    priv,
  };

  const filename = join(outDir, `${alg}.json`);
  writeFileSync(filename, JSON.stringify(jwk, null, 2) + "\n");
  console.log(`Wrote ${filename}`);
}

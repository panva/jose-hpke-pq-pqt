import {
  KEM_MLKEM768_P256,
  KEM_MLKEM768_X25519,
  KEM_MLKEM1024_P384,
  KEM_ML_KEM_768,
  KEM_ML_KEM_1024,
  KDF_SHAKE256,
  AEAD_AES_256_GCM,
  AEAD_ChaCha20Poly1305,
} from "hpke";

// HPKE-1 through HPKE-7 are registered by I-D.ietf-jose-hpke-encrypt.
// startIndex sets the first "alg" number so that algorithms defined here
// are named HPKE-8, HPKE-9, ... continuing from where that document ends.
const startIndex = 8;

// Each suite is [KEM, KDF, AEAD] or [KEM, KDF, AEAD, options].
// By default both an integrated encryption and a -KE (Key Encryption)
// variant are emitted for each suite. To suppress the -KE variant pass
// { ke: false } as the fourth element, e.g.:
//   [KEM_ML_KEM_768, KDF_SHAKE256, AEAD_ChaCha20Poly1305, { ke: false }]
const suites = [
  // PQ/T Hybrid
  [KEM_MLKEM768_P256, KDF_SHAKE256, AEAD_AES_256_GCM],
  [KEM_MLKEM768_P256, KDF_SHAKE256, AEAD_ChaCha20Poly1305],
  [KEM_MLKEM768_X25519, KDF_SHAKE256, AEAD_AES_256_GCM],
  [KEM_MLKEM768_X25519, KDF_SHAKE256, AEAD_ChaCha20Poly1305],
  [KEM_MLKEM1024_P384, KDF_SHAKE256, AEAD_AES_256_GCM],
  [KEM_MLKEM1024_P384, KDF_SHAKE256, AEAD_ChaCha20Poly1305],
  // Pure PQ
  [KEM_ML_KEM_768, KDF_SHAKE256, AEAD_AES_256_GCM],
  [KEM_ML_KEM_768, KDF_SHAKE256, AEAD_ChaCha20Poly1305],
  [KEM_ML_KEM_1024, KDF_SHAKE256, AEAD_AES_256_GCM],
  [KEM_ML_KEM_1024, KDF_SHAKE256, AEAD_ChaCha20Poly1305],
];

export const algorithms = suites.flatMap(([kem, kdf, aead, options], i) => {
  const alg = `HPKE-${startIndex + i}`;
  const result = [{ alg, kem, kdf, aead }];
  if (options?.ke !== false) {
    result.push({ alg: `${alg}-KE`, kem, kdf, aead });
  }
  return result;
});

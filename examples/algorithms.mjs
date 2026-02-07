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

const suites = [
  // PQ/T Hybrid
  ["HPKE-8", KEM_MLKEM768_P256, AEAD_AES_256_GCM],
  ["HPKE-9", KEM_MLKEM768_P256, AEAD_ChaCha20Poly1305],
  ["HPKE-10", KEM_MLKEM768_X25519, AEAD_AES_256_GCM],
  ["HPKE-11", KEM_MLKEM768_X25519, AEAD_ChaCha20Poly1305],
  ["HPKE-12", KEM_MLKEM1024_P384, AEAD_AES_256_GCM],
  ["HPKE-13", KEM_MLKEM1024_P384, AEAD_ChaCha20Poly1305],
  // Pure PQ
  ["HPKE-14", KEM_ML_KEM_768, AEAD_AES_256_GCM],
  ["HPKE-15", KEM_ML_KEM_768, AEAD_ChaCha20Poly1305],
  ["HPKE-16", KEM_ML_KEM_1024, AEAD_AES_256_GCM],
  ["HPKE-17", KEM_ML_KEM_1024, AEAD_ChaCha20Poly1305],
];

export const algorithms = suites.flatMap(([alg, kem, aead]) => [
  { alg, kem, kdf: KDF_SHAKE256, aead },
  { alg: `${alg}-KE`, kem, kdf: KDF_SHAKE256, aead },
]);

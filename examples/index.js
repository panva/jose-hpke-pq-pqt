import { CipherSuite } from "hpke";
import { algorithms } from "./algorithms.js";

import { readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const draftPath = join(__dirname, "..", "draft-skokan-jose-hpke-pq-pqt.md");

// Hash algorithms.js to detect any change in suite definitions
const algorithmsPath = join(__dirname, "algorithms.js");
const algorithmsHash = createHash("sha256")
  .update(readFileSync(algorithmsPath))
  .digest("hex");
const hashPath = join(__dirname, ".algorithms-hash");
const previousHash = existsSync(hashPath)
  ? readFileSync(hashPath, "utf8").trim()
  : null;

const force = process.argv.includes("--force");

const jwksDir = join(__dirname, "jwks");
const jweDir = join(__dirname, "jwe");

if (
  !force &&
  previousHash === algorithmsHash &&
  existsSync(jwksDir) &&
  existsSync(jweDir)
) {
  console.log("Examples up to date, skipping regeneration.");
} else {
  // Clean and regenerate example outputs
  rmSync(jwksDir, { recursive: true, force: true });
  rmSync(jweDir, { recursive: true, force: true });
  execFileSync(
    process.execPath,
    ["--no-warnings", join(__dirname, "jwks.js")],
    {
      stdio: "inherit",
    },
  );
  execFileSync(
    process.execPath,
    ["--no-warnings", join(__dirname, "jwe.js")],
    {
      stdio: "inherit",
    },
  );
  writeFileSync(hashPath, algorithmsHash + "\n");
}

// Build enriched algorithm entries with CipherSuite metadata
const entries = algorithms.map(({ alg, kem, kdf, aead }) => {
  const suite = new CipherSuite(kem, kdf, aead);
  const isKE = alg.endsWith("-KE");
  const baseAlg = isKE ? alg.slice(0, -3) : alg;
  // PQ/T hybrid KEMs have a traditional component (contain a hyphen-separated
  // curve name like P256, X25519, P384). Pure PQ KEMs start with "ML-KEM-".
  const isPQT = !suite.KEM.name.startsWith("ML-KEM-");
  return { alg, baseAlg, isKE, isPQT, suite };
});

const base = entries.filter((e) => !e.isKE);
const ke = entries.filter((e) => e.isKE);
const pqtBase = base.filter((e) => e.isPQT);
const purePQBase = base.filter((e) => !e.isPQT);
const pqtKE = ke.filter((e) => e.isPQT);
const purePQKE = ke.filter((e) => !e.isPQT);

// --- Helpers ---

function hexId(id) {
  return `\`0x${id.toString(16).padStart(4, "0")}\``;
}

function cellValues(entry) {
  const { alg, suite } = entry;
  return {
    alg,
    kem: `${suite.KEM.name} (${hexId(suite.KEM.id)})`,
    kdf: `${suite.KDF.name} (${hexId(suite.KDF.id)})`,
    aead: `${suite.AEAD.name} (${hexId(suite.AEAD.id)})`,
  };
}

function buildTable(rows) {
  const headers = ['"alg" value', "HPKE KEM", "HPKE KDF", "HPKE AEAD"];
  const data = rows.map(cellValues);

  // Compute column widths from headers and all data rows
  const widths = headers.map((h, i) => {
    const key = ["alg", "kem", "kdf", "aead"][i];
    return Math.max(h.length, ...data.map((d) => d[key].length));
  });

  const line = (cells) =>
    "| " + cells.map((c, i) => c.padEnd(widths[i])).join(" | ") + " |";
  const sep = "| " + widths.map((w) => "-".repeat(w)).join(" | ") + " |";

  return [
    line(headers),
    sep,
    ...data.map((d) => line([d.alg, d.kem, d.kdf, d.aead])),
  ].join("\n");
}

function ianaEntry(entry) {
  const { alg, isKE, isPQT, suite } = entry;
  const mode = isKE ? "Key Encryption" : "Integrated Encryption";
  const integratedTable = isPQT
    ? "pqt-hybrid-integrated-table"
    : "pure-pq-integrated-table";
  const keTable = isPQT
    ? "pqt-hybrid-key-encryption-table"
    : "pure-pq-key-encryption-table";
  const specTable = isKE ? keTable : integratedTable;

  return `### ${alg}
{: toc="exclude"}

- Algorithm Name: ${alg}
- Algorithm Description: ${mode} with HPKE using ${suite.KEM.name} KEM, ${suite.KDF.name} KDF, and ${suite.AEAD.name} AEAD
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IETF
- Specification Document(s): {{${specTable}}} of this document
- Algorithm Analysis Document(s): {{I-D.ietf-hpke-pq}}`;
}

function testVectorSection(entry) {
  const { alg } = entry;
  return `## ${alg}
{: toc="exclude"}

~~~ json
{::include examples/jwks/${alg}.json}
~~~
{: title="${alg} Private JWK"}

~~~ json
{::include examples/jwe/${alg}-flattened.json}
~~~
{: title="${alg} Flattened JWE JSON Serialization"}

~~~
{::include examples/jwe/${alg}-compact.txt}
~~~
{: title="${alg} JWE Compact Serialization"}`;
}

// --- Generate IANA section ---

function generateIANA() {
  // Interleave: base alg, then its -KE variant
  const ianaEntries = [];
  for (const b of base) {
    ianaEntries.push(ianaEntry(b));
    const keVariant = ke.find((k) => k.baseAlg === b.baseAlg);
    ianaEntries.push(ianaEntry(keVariant));
  }
  return ianaEntries.join("\n\n");
}

// --- Generate test vectors ---

function generateTestVectors() {
  // Same interleaved order: base alg, then -KE
  const sections = [];
  for (const b of base) {
    sections.push(testVectorSection(b));
    const keVariant = ke.find((k) => k.baseAlg === b.baseAlg);
    sections.push(testVectorSection(keVariant));
  }
  return sections.join("\n\n");
}

// --- Apply to draft ---

let draft = readFileSync(draftPath, "utf8");

function replaceSection(name, content) {
  const beginMarker = `<!-- begin:${name} ; see README for regeneration instructions, do not edit -->`;
  const endMarker = `<!-- end:${name} -->`;
  const beginIdx = draft.indexOf(beginMarker);
  const endIdx = draft.indexOf(endMarker);
  if (beginIdx === -1 || endIdx === -1) {
    throw new Error(`Could not find ${name} section markers in draft`);
  }
  draft =
    draft.slice(0, beginIdx + beginMarker.length) +
    "\n\n" +
    content +
    "\n\n" +
    draft.slice(endIdx);
}

// Map table ids to the rows they should contain
const tableRows = {
  "pqt-hybrid-integrated-table": pqtBase,
  "pure-pq-integrated-table": purePQBase,
  "pqt-hybrid-key-encryption-table": pqtKE,
  "pure-pq-key-encryption-table": purePQKE,
};

// Find all table markers and replace their content
const tableMarkerRe =
  /<!-- begin:table (\S+) "([^"]+)" ; see README for regeneration instructions, do not edit -->/g;
for (const match of draft.matchAll(tableMarkerRe)) {
  const [beginMarker, id, title] = match;
  const endMarker = "<!-- end:table -->";
  const beginIdx = draft.indexOf(beginMarker);
  const endIdx = draft.indexOf(endMarker, beginIdx);
  if (endIdx === -1) {
    throw new Error(`Could not find end:table marker for ${id}`);
  }
  const rows = tableRows[id];
  if (!rows) {
    throw new Error(`Unknown table id: ${id}`);
  }
  const table = buildTable(rows);
  const content = `${table}\n{: #${id} title="${title}" }`;
  draft =
    draft.slice(0, beginIdx + beginMarker.length) +
    "\n\n" +
    content +
    "\n\n" +
    draft.slice(endIdx);
}

replaceSection("iana-registrations", generateIANA());
replaceSection("test-vectors", generateTestVectors());

writeFileSync(draftPath, draft);
console.log("Draft updated successfully.");

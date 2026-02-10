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

export default function buildTable(rows) {
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

// Test-only cross-language verifier. The fixed seed is public test material.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalizeFasp } from "../../bridge_core/fasp_canonical.mjs";

const input = JSON.parse(readFileSync(0, "utf8"));
const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(input.test_seed_hex, "hex")]), format: "der", type: "pkcs8" });
const publicKey = createPublicKey(privateKey);
const publicRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
const records = input.records.map(record => {
  const { signature, ...unsigned } = record;
  const bytes = canonicalizeFasp(unsigned);
  return {
    canonical_b64: bytes.toString("base64url"),
    signature_b64: sign(null, bytes, privateKey).toString("base64url"),
    python_signature_valid: verify(null, bytes, publicKey, Buffer.from(signature.value, "base64url")),
  };
});
const rejects = input.invalid.map(value => {
  try { canonicalizeFasp(value); return false; } catch { return true; }
});
process.stdout.write(JSON.stringify({
  public_key: publicRaw.toString("base64url"),
  system_id: `fasp:system:${createHash("sha256").update(publicRaw).digest("base64url")}`,
  records, rejects,
}));

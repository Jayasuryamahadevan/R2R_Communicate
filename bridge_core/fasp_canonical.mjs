/** FASP wire JCS serialization. Uses ECMAScript's number formatting and
 * UTF-16 property ordering as required by RFC 8785. The FASP profile also
 * rejects unsafe integral values, undefined, and lone UTF-16 surrogates.
 * AIC's separate, deliberately restricted canonicalizer is unchanged.
 */
export function canonicalizeFasp(value) {
  let nodes = 0;
  function string(text) {
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = text.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("Invalid Unicode scalar value");
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new TypeError("Invalid Unicode scalar value");
      }
    }
    return JSON.stringify(text);
  }
  function encode(item, depth) {
    if (++nodes > 8192 || depth > 32) throw new TypeError("FASP JSON structure limit exceeded");
    if (item === null) return "null";
    if (typeof item === "string") return string(item);
    if (typeof item === "boolean") return JSON.stringify(item);
    if (typeof item === "number") {
      if (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item))) {
        throw new TypeError("FASP number is non-finite or outside the safe integer range");
      }
      return JSON.stringify(item);
    }
    if (Array.isArray(item)) {
      const parts = [];
      for (let i = 0; i < item.length; i++) parts.push(encode(item[i], depth + 1));
      return `[${parts.join(",")}]`;
    }
    if (typeof item === "object" && (Object.getPrototypeOf(item) === Object.prototype || Object.getPrototypeOf(item) === null)) {
      return `{${Object.keys(item).sort().map(key => {
        if (++nodes > 8192 || depth + 1 > 32) throw new TypeError("FASP JSON structure limit exceeded");
        return `${string(key)}:${encode(item[key], depth + 1)}`;
      }).join(",")}}`;
    }
    throw new TypeError("Only JSON values are accepted by FASP");
  }
  const encoded = Buffer.from(encode(value, 0), "utf8");
  if (encoded.length > 65536) throw new TypeError("FASP record exceeds 64 KiB");
  return encoded;
}

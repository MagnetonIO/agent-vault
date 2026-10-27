import { SecretNotTextError } from "./errors.js";

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** `bytes` as UTF-8 text, kept exactly (a BOM stays). Throws SecretNotTextError, naming only `name`. */
export function decodeSecretText(name: string, bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes);
  } catch {
    throw new SecretNotTextError(name);
  }
}

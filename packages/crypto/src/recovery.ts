import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

const KEY_LEN = 32;
const WORD_COUNT = 24;

export function recoveryWords(key: Uint8Array): string[] {
  if (key.length !== KEY_LEN) throw new RangeError("recovery key must be 32 bytes");
  return entropyToMnemonic(key, wordlist).split(" ");
}

/** Throws on unknown words, wrong word count, or a bad checksum. */
export function keyFromRecoveryWords(words: string[]): Uint8Array {
  if (words.length !== WORD_COUNT) throw new RangeError(`expected ${WORD_COUNT} recovery words`);
  return mnemonicToEntropy(words.join(" "), wordlist);
}

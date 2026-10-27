import fs from "node:fs";

/**
 * Test-only: when this names a file, the clipboard is that file. The CLI reads it and empties it
 * instead of touching the system clipboard. It is a path, never a secret.
 */
export const TEST_CLIPBOARD_ENV = "AGENT_VAULT_TEST_CLIPBOARD_FILE";

export async function readClipboard(): Promise<string> {
  const file = process.env[TEST_CLIPBOARD_ENV];
  if (file) return fs.readFileSync(file, "utf8");
  const { default: clipboard } = await import("clipboardy");
  return clipboard.read();
}

export async function clearClipboard(): Promise<void> {
  const file = process.env[TEST_CLIPBOARD_ENV];
  if (file) {
    fs.writeFileSync(file, "");
    return;
  }
  const { default: clipboard } = await import("clipboardy");
  await clipboard.write("");
}

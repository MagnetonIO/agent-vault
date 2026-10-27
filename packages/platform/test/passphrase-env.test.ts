import { describe, expect, test } from "vitest";
import { childBaseEnv, PASSPHRASE_ENV } from "../src/index.js";

describe("childBaseEnv", () => {
  test("keeps every set variable but the keyfile passphrase", () => {
    const env = { PATH: "/bin", HOME: "/h", [PASSPHRASE_ENV]: "pw", GONE: undefined };
    expect(childBaseEnv(env)).toEqual({ PATH: "/bin", HOME: "/h" });
    expect(PASSPHRASE_ENV).toBe("AGENT_VAULT_KEYFILE_PASSPHRASE");
  });
});

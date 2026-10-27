import path from "node:path";
import { describe, expect, test } from "vitest";
import {
  allowExe,
  BundleExistsError,
  BundleNotFoundError,
  createBundle,
  grant,
  InvalidEnvNameError,
  InvalidExePathError,
  InvalidNameError,
  listBundles,
  MetadataTamperError,
  resolveBundle,
  SecretNotFoundError,
  VaultClosedError,
} from "../src/index.js";
import { enc, useVaultEnv } from "./helpers.js";

const env = useVaultEnv();

async function seeded() {
  const v = await env.newVault();
  v.putSecret("github/token", enc.encode("ghp_x"));
  v.putSecret("stripe/key", enc.encode("sk_x"));
  return v;
}

const exe = (name: string) => path.resolve(path.sep, "usr", "bin", name);

describe("bundles", () => {
  test("resolveBundle returns the granted env map and exes", async () => {
    const v = await seeded();
    createBundle(v, "deploy");
    grant(v, "deploy", { env: "GITHUB_TOKEN", secret: "github/token" });
    grant(v, "deploy", { env: "STRIPE_KEY", secret: "stripe/key" });
    allowExe(v, "deploy", exe("git"));
    expect(resolveBundle(v, "deploy")).toEqual({
      env: { GITHUB_TOKEN: "github/token", STRIPE_KEY: "stripe/key" },
      exes: [exe("git")],
    });
  });

  test("a new bundle is empty", async () => {
    const v = await seeded();
    createBundle(v, "empty");
    expect(resolveBundle(v, "empty")).toEqual({ env: {}, exes: [] });
  });

  test("re-granting an env name replaces the mapping", async () => {
    const v = await seeded();
    createBundle(v, "b");
    grant(v, "b", { env: "TOKEN", secret: "github/token" });
    grant(v, "b", { env: "TOKEN", secret: "stripe/key" });
    expect(resolveBundle(v, "b").env).toEqual({ TOKEN: "stripe/key" });
  });

  test("allowing the same exe twice stores it once; exes come back sorted", async () => {
    const v = await seeded();
    createBundle(v, "b");
    allowExe(v, "b", exe("zsh"));
    allowExe(v, "b", exe("awk"));
    allowExe(v, "b", exe("zsh"));
    expect(resolveBundle(v, "b").exes).toEqual([exe("awk"), exe("zsh")]);
  });

  test("createBundle on an existing name throws BundleExistsError", async () => {
    const v = await seeded();
    createBundle(v, "b");
    expect(() => createBundle(v, "b")).toThrow(BundleExistsError);
  });

  test("bundle names follow the secret-name rule", async () => {
    const v = await seeded();
    for (const bad of ["", "Upper", "-x", "a b", "a//b", "a".repeat(129)]) {
      expect(() => createBundle(v, bad)).toThrow(InvalidNameError);
    }
    createBundle(v, "team/ci.deploy-1");
    expect(() => grant(v, "Bad", { env: "A", secret: "github/token" })).toThrow(InvalidNameError);
    expect(() => allowExe(v, "Bad", exe("git"))).toThrow(InvalidNameError);
    expect(() => resolveBundle(v, "Bad")).toThrow(InvalidNameError);
  });

  test("grant rejects bad env names", async () => {
    const v = await seeded();
    createBundle(v, "b");
    for (const bad of ["", "1A", "A-B", "A B", "A=B", "A\n", "a.b"]) {
      expect(() => grant(v, "b", { env: bad, secret: "github/token" })).toThrow(
        InvalidEnvNameError,
      );
    }
    grant(v, "b", { env: "_ok1", secret: "github/token" });
    expect(resolveBundle(v, "b").env).toEqual({ _ok1: "github/token" });
  });

  test("grant needs an existing secret and an existing bundle", async () => {
    const v = await seeded();
    createBundle(v, "b");
    expect(() => grant(v, "b", { env: "A", secret: "nope" })).toThrow(SecretNotFoundError);
    expect(() => grant(v, "missing", { env: "A", secret: "github/token" })).toThrow(
      BundleNotFoundError,
    );
    expect(() => allowExe(v, "missing", exe("git"))).toThrow(BundleNotFoundError);
    expect(() => resolveBundle(v, "missing")).toThrow(BundleNotFoundError);
    expect(resolveBundle(v, "b").env).toEqual({});
  });

  test("allowExe requires an absolute path", async () => {
    const v = await seeded();
    createBundle(v, "b");
    for (const bad of ["", "git", "./git", "bin/git", "~/bin/git"]) {
      expect(() => allowExe(v, "b", bad)).toThrow(InvalidExePathError);
    }
    expect(resolveBundle(v, "b").exes).toEqual([]);
  });

  test("listBundles returns every bundle sorted by name", async () => {
    const v = await seeded();
    createBundle(v, "zeta");
    createBundle(v, "alpha");
    grant(v, "alpha", { env: "T", secret: "github/token" });
    allowExe(v, "alpha", exe("git"));
    expect(listBundles(v)).toEqual([
      { name: "alpha", env: { T: "github/token" }, exes: [exe("git")] },
      { name: "zeta", env: {}, exes: [] },
    ]);
  });

  test("bundles survive close and reopen", async () => {
    const v = await seeded();
    createBundle(v, "b");
    grant(v, "b", { env: "T", secret: "github/token" });
    allowExe(v, "b", exe("git"));
    v.close();
    const { openVault } = await import("../src/index.js");
    const again = await openVault({ paths: env.paths, store: env.store });
    try {
      expect(resolveBundle(again, "b")).toEqual({
        env: { T: "github/token" },
        exes: [exe("git")],
      });
    } finally {
      again.close();
    }
  });

  test("every call on a closed vault throws VaultClosedError", async () => {
    const v = await seeded();
    createBundle(v, "b");
    v.close();
    expect(() => createBundle(v, "c")).toThrow(VaultClosedError);
    expect(() => grant(v, "b", { env: "A", secret: "github/token" })).toThrow(VaultClosedError);
    expect(() => allowExe(v, "b", exe("git"))).toThrow(VaultClosedError);
    expect(() => resolveBundle(v, "b")).toThrow(VaultClosedError);
    expect(() => listBundles(v)).toThrow(VaultClosedError);
  });
});

describe("bundle integrity", () => {
  async function granted() {
    const v = await seeded();
    createBundle(v, "b");
    grant(v, "b", { env: "TOKEN", secret: "github/token" });
    allowExe(v, "b", exe("git"));
    return v;
  }

  test("editing bundle_env to redirect an env var is detected", async () => {
    const v = await granted();
    env.withRawDb((db) =>
      db
        .prepare("UPDATE bundle_env SET secret_name = ? WHERE env_name = ?")
        .run("stripe/key", "TOKEN"),
    );
    expect(() => resolveBundle(v, "b")).toThrow(MetadataTamperError);
    expect(() => listBundles(v)).toThrow(MetadataTamperError);
  });

  test("adding a bundle_env row is detected", async () => {
    const v = await granted();
    env.withRawDb((db) =>
      db
        .prepare(
          "INSERT INTO bundle_env (bundle_id, env_name, secret_name) SELECT id, 'EXTRA', 'stripe/key' FROM bundles WHERE name = 'b'",
        )
        .run(),
    );
    expect(() => resolveBundle(v, "b")).toThrow(MetadataTamperError);
  });

  test("removing a bundle_env row is detected", async () => {
    const v = await granted();
    env.withRawDb((db) => db.exec("DELETE FROM bundle_env"));
    expect(() => resolveBundle(v, "b")).toThrow(MetadataTamperError);
  });

  test("editing the exe list is detected", async () => {
    const v = await granted();
    env.withRawDb((db) => db.prepare("UPDATE bundle_exes SET exe_path = ?").run(exe("evil")));
    expect(() => resolveBundle(v, "b")).toThrow(MetadataTamperError);
  });

  test("adding an exe row is detected", async () => {
    const v = await granted();
    env.withRawDb((db) =>
      db
        .prepare(
          "INSERT INTO bundle_exes (bundle_id, exe_path) SELECT id, ? FROM bundles WHERE name = 'b'",
        )
        .run(exe("evil")),
    );
    expect(() => resolveBundle(v, "b")).toThrow(MetadataTamperError);
  });

  test("renaming a bundle is detected", async () => {
    const v = await granted();
    env.withRawDb((db) => db.exec("UPDATE bundles SET name = 'renamed'"));
    expect(() => resolveBundle(v, "renamed")).toThrow(MetadataTamperError);
  });

  test("an unsigned bundle inserted straight into SQL is rejected", async () => {
    const v = await granted();
    env.withRawDb((db) => {
      db.prepare("INSERT INTO bundles (id, name, meta_mac) VALUES ('x', 'sneaky', ?)").run(
        new Uint8Array(32),
      );
    });
    expect(() => resolveBundle(v, "sneaky")).toThrow(MetadataTamperError);
    expect(() => listBundles(v)).toThrow(MetadataTamperError);
  });

  test("grant and allowExe refuse to re-MAC a tampered bundle", async () => {
    const v = await granted();
    env.withRawDb((db) => db.prepare("UPDATE bundle_env SET secret_name = 'stripe/key'").run());
    expect(() => grant(v, "b", { env: "OTHER", secret: "github/token" })).toThrow(
      MetadataTamperError,
    );
    expect(() => allowExe(v, "b", exe("ls"))).toThrow(MetadataTamperError);
  });

  test("an env/exe boundary shift does not collide", async () => {
    const v = await granted();
    // Moving the exe path into bundle_env keeps the multiset of strings; the counts differ.
    env.withRawDb((db) => {
      db.exec("DELETE FROM bundle_exes");
      db.prepare(
        "INSERT INTO bundle_env (bundle_id, env_name, secret_name) SELECT id, 'X', ? FROM bundles",
      ).run(exe("git"));
    });
    expect(() => resolveBundle(v, "b")).toThrow(MetadataTamperError);
  });
});

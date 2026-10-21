import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  SecondFactorClient,
  SecondFactorError,
  signAssertion,
  bodyHash,
} from "../dist/index.js";
const vectors = JSON.parse(
  readFileSync(
    new URL("../../../testdata/assertion_vectors.json", import.meta.url),
  ),
);
for (const v of vectors.valid)
  test(v.name, () => {
    assert.equal(bodyHash(Buffer.from(v.body_base64, "base64")), v.claims.bsh);
    assert.equal(
      signAssertion(Buffer.from(v.seed_hex, "hex"), v.key_id, v.claims),
      v.assertion,
    );
  });
test("rejects unsafe configuration", () => {
  assert.throws(
    () =>
      new SecondFactorClient({
        baseURL: "http://evil.example",
        seed: new Uint8Array(32),
        application: "a",
        audience: "b",
        keyID: "k",
      }),
  );
});
test("maps structured errors and disallows redirects", async () => {
  const c = new SecondFactorClient({
    baseURL: "http://127.0.0.1:9999",
    seed: new Uint8Array(32),
    application: "a",
    audience: "b",
    keyID: "k",
    fetch: async (url, init) => {
      assert.equal(init.redirect, "error");
      return new Response(
        JSON.stringify({
          error: {
            code: "rate_limited",
            message: "Slow down",
            retry_after: 600,
          },
        }),
        { status: 429 },
      );
    },
  });
  await assert.rejects(
    c.status({ subject: "u", session: "s", source: "test" }),
    (e) =>
      e instanceof SecondFactorError &&
      e.code === "rate_limited" &&
      e.retryAfter === 600,
  );
});
test(
  "live Go service status and denial",
  { skip: !process.env.SF_TEST_URL },
  async () => {
    const c = new SecondFactorClient({
      baseURL: process.env.SF_TEST_URL,
      seed: Buffer.from(vectors.valid[0].seed_hex, "hex"),
      application: "test",
      audience: "secondfactor-test",
      keyID: "test",
    });
    const i = {
      subject: "sdk-user",
      session: "sdk-session",
      source: "sdk-test",
    };
    assert.equal((await c.status(i)).enrolled, false);
    await assert.rejects(
      c.validateProof(i, "invalid", "access"),
      (e) => e.code === "denied",
    );
  },
);

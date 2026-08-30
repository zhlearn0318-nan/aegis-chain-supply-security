import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import {
  UploadError,
  UploadSessionStore,
  decodeRelativePath,
  validateTargetName,
} from "./upload_sessions.js";


function encoded(value) {
  return Buffer.from(value, "utf8").toString("base64url");
}


function requestFor(content) {
  const request = Readable.from([Buffer.from(content)]);
  request.headers = { "content-length": String(Buffer.byteLength(content)) };
  return request;
}


test("relative upload paths preserve a safe browser directory", () => {
  assert.equal(decodeRelativePath(encoded("weather/scripts/run.py")), "weather/scripts/run.py");
});


test("relative upload paths require canonical UTF-8", () => {
  assert.throws(() => decodeRelativePath("_w"), UploadError);
  assert.throws(() => decodeRelativePath(encoded("folder/control\u0001.py")), UploadError);
});


for (const unsafe of ["../escape.py", "folder\\escape.py", "CON/file.py", "folder/bad:name.py", "/absolute.py"]) {
  test(`unsafe path is rejected: ${unsafe}`, () => {
    assert.throws(() => decodeRelativePath(encoded(unsafe)), UploadError);
  });
}


test("target name uses the OpenClaw-safe slug contract", () => {
  assert.equal(validateTargetName("safe-skill_1"), "safe-skill_1");
  assert.throws(() => validateTargetName("../unsafe"), UploadError);
  assert.throws(() => validateTargetName("CON"), UploadError);
});


test("folder upload is written only below the random session", async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "aegis-upload-test-"));
  try {
    const store = new UploadSessionStore(root);
    const session = store.create({ sourceKind: "folder", targetName: "safe-skill", displayName: "safe" });
    const result = await store.receiveFile(requestFor("safe"), session, encoded("skill/SKILL.md"));
    const stored = path.join(session.root, "incoming", "folder", "skill", "SKILL.md");
    assert.deepEqual(result, { file_count: 1, total_bytes: 4 });
    assert.equal(readFileSync(stored, "utf8"), "safe");
    store.remove(session.id);
    assert.equal(existsSync(session.root), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});


test("duplicate case-insensitive folder paths are rejected", async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "aegis-upload-test-"));
  try {
    const store = new UploadSessionStore(root);
    const session = store.create({ sourceKind: "folder", targetName: "safe-skill", displayName: "safe" });
    await store.receiveFile(requestFor("one"), session, encoded("skill/run.py"));
    await assert.rejects(
      () => store.receiveFile(requestFor("two"), session, encoded("SKILL/RUN.PY")),
      (error) => error instanceof UploadError && error.code === "UPLOAD_DUPLICATE_PATH",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

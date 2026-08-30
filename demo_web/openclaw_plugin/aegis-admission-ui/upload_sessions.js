import { randomBytes } from "node:crypto";
import { createWriteStream, mkdirSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";


export const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024;
export const MAX_EXPANDED_BYTES = 200 * 1024 * 1024;
export const MAX_FILES = 5_000;
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
export const SESSION_TTL_MS = 30 * 60 * 1000;
const TARGET_NAME = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const WINDOWS_RESERVED = new Set([
  "con", "prn", "aux", "nul", "clock$",
  ...Array.from({ length: 9 }, (_, index) => `com${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `lpt${index + 1}`),
]);


export class UploadError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "UploadError";
    this.code = code;
    this.status = status;
  }
}


export function validateTargetName(value) {
  const name = String(value ?? "").trim().toLowerCase();
  if (!TARGET_NAME.test(name) || WINDOWS_RESERVED.has(name)) {
    throw new UploadError(
      "TARGET_NAME_INVALID",
      "Skill 安装名称仅允许 1-64 位小写字母、数字、点、下划线和连字符。",
    );
  }
  return name;
}


export function decodeRelativePath(encoded) {
  const value = String(encoded ?? "");
  if (!value || value.length > 1_024 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new UploadError("UPLOAD_PATH_INVALID", "上传文件的相对路径编码无效。");
  }
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url").toString("utf8");
  } catch {
    throw new UploadError("UPLOAD_PATH_INVALID", "上传文件的相对路径编码无效。");
  }
  if (Buffer.from(decoded, "utf8").toString("base64url") !== value.replace(/=+$/u, "")) {
    throw new UploadError("UPLOAD_PATH_INVALID", "上传文件的相对路径不是规范 UTF-8 编码。");
  }
  if (!decoded || /[\u0000-\u001f\u007f]/u.test(decoded) || decoded.includes("\\") || decoded.length > 240) {
    throw new UploadError("UPLOAD_PATH_INVALID", "上传文件路径不符合 Windows 安全边界。");
  }
  const parts = decoded.split("/");
  if (parts.some((part) => !part || part === "." || part === ".." || part.endsWith(" ") || part.endsWith("."))) {
    throw new UploadError("UPLOAD_PATH_INVALID", "上传文件路径包含穿越或非法目录段。");
  }
  for (const part of parts) {
    if (/[<>:"|?*]/u.test(part) || WINDOWS_RESERVED.has(part.split(".", 1)[0].toLowerCase())) {
      throw new UploadError("UPLOAD_PATH_INVALID", "上传文件路径包含 Windows 非法文件名。");
    }
  }
  return parts.join("/");
}


export async function writeRequestBody(req, destination, maxBytes) {
  const declared = Number(req.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new UploadError("UPLOAD_SIZE_LIMIT", `上传内容超过 ${Math.floor(maxBytes / 1024 / 1024)} MB 上限。`, 413);
  }
  let size = 0;
  const limiter = new Transform({
    transform(chunk, _encoding, callback) {
      size += chunk.length;
      if (size > maxBytes) {
        callback(new UploadError("UPLOAD_SIZE_LIMIT", `上传内容超过 ${Math.floor(maxBytes / 1024 / 1024)} MB 上限。`, 413));
      } else callback(null, chunk);
    },
  });
  try {
    await pipeline(req, limiter, createWriteStream(destination, { flags: "wx" }));
  } catch (error) {
    rmSync(destination, { force: true });
    throw error;
  }
  if (size < 1) {
    rmSync(destination, { force: true });
    throw new UploadError("UPLOAD_EMPTY", "不接受空文件。");
  }
  return size;
}


export class UploadSessionStore {
  constructor(root, { maxSessions = 10, ttlMs = SESSION_TTL_MS } = {}) {
    this.root = path.resolve(root);
    this.maxSessions = maxSessions;
    this.ttlMs = ttlMs;
    this.sessions = new Map();
    mkdirSync(this.root, { recursive: true });
    // Sessions are intentionally memory-bound. After a gateway restart no
    // browser holds a valid install capability, so remove only exact random
    // session directories left by the previous process.
    for (const entry of readdirSync(this.root, { withFileTypes: true })) {
      if (entry.isDirectory() && !entry.isSymbolicLink() && /^[0-9a-f]{32}$/u.test(entry.name)) {
        rmSync(path.join(this.root, entry.name), { recursive: true, force: true });
      }
    }
  }

  cleanupExpired(now = Date.now()) {
    for (const [id, session] of this.sessions) {
      if (!session.running && now - session.updatedAt > this.ttlMs) this.remove(id);
    }
  }

  create({ sourceKind, targetName, displayName }) {
    this.cleanupExpired();
    if (!new Set(["zip", "folder"]).has(sourceKind)) {
      throw new UploadError("SOURCE_KIND_INVALID", "仅支持 ZIP 压缩包或本地文件夹。");
    }
    if (this.sessions.size >= this.maxSessions) {
      throw new UploadError("SESSION_LIMIT", "上传会话已满，请稍后重试。", 429);
    }
    const id = randomBytes(16).toString("hex");
    const root = path.join(this.root, id);
    const incoming = path.join(root, "incoming");
    mkdirSync(incoming, { recursive: true });
    const now = Date.now();
    const session = {
      id,
      root,
      sourceKind,
      targetName: validateTargetName(targetName),
      displayName: String(displayName ?? "").slice(0, 200),
      createdAt: now,
      updatedAt: now,
      fileCount: 0,
      totalBytes: 0,
      relativePaths: new Set(),
      running: false,
      state: "uploading",
      scan: null,
      sourceRoot: null,
      installed: false,
    };
    this.sessions.set(id, session);
    return session;
  }

  get(id) {
    this.cleanupExpired();
    if (!/^[0-9a-f]{32}$/u.test(String(id ?? ""))) {
      throw new UploadError("SESSION_INVALID", "上传会话标识无效。", 404);
    }
    const session = this.sessions.get(id);
    if (!session) throw new UploadError("SESSION_EXPIRED", "上传会话不存在或已过期，请重新上传。", 404);
    session.updatedAt = Date.now();
    return session;
  }

  remove(id) {
    const session = this.sessions.get(id);
    if (!session) return;
    this.sessions.delete(id);
    const expected = path.join(this.root, id);
    if (session.root === expected && /^[0-9a-f]{32}$/u.test(id)) {
      rmSync(expected, { recursive: true, force: true });
    }
  }

  async receiveFile(req, session, encodedRelativePath = "") {
    if (session.running || session.state !== "uploading") {
      throw new UploadError("SESSION_STATE_INVALID", "当前会话不再接受上传文件。", 409);
    }
    if (session.sourceKind === "zip") {
      if (session.fileCount !== 0) throw new UploadError("ZIP_COUNT_INVALID", "ZIP 会话只能上传一个压缩包。", 409);
      const destination = path.join(session.root, "incoming", "upload.zip");
      const size = await writeRequestBody(req, destination, MAX_ARCHIVE_BYTES);
      session.fileCount = 1;
      session.totalBytes = size;
    } else {
      const relative = decodeRelativePath(encodedRelativePath);
      const key = relative.toLowerCase();
      if (session.relativePaths.has(key)) throw new UploadError("UPLOAD_DUPLICATE_PATH", "文件夹包含重复或大小写冲突路径。", 409);
      if (session.fileCount >= MAX_FILES) throw new UploadError("SOURCE_FILE_LIMIT", "Skill 文件数量超过 5,000。", 413);
      const remaining = MAX_EXPANDED_BYTES - session.totalBytes;
      if (remaining <= 0) throw new UploadError("SOURCE_TOTAL_SIZE_LIMIT", "Skill 总大小超过 200 MB。", 413);
      const maxBytes = Math.min(MAX_FILE_BYTES, remaining);
      const destination = path.join(session.root, "incoming", "folder", ...relative.split("/"));
      mkdirSync(path.dirname(destination), { recursive: true });
      const size = await writeRequestBody(req, destination, maxBytes);
      session.relativePaths.add(key);
      session.fileCount += 1;
      session.totalBytes += size;
    }
    session.updatedAt = Date.now();
    return { file_count: session.fileCount, total_bytes: session.totalBytes };
  }
}

#!/usr/bin/env node

import { spawnSync } from "node:child_process";


const PROTOCOL_VERSION = 1;
const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 1024 * 1024;


function boundedText(value, fallback, limit = 300) {
  const normalized = String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return (normalized || fallback).slice(0, limit);
}


function block(ruleId, reason) {
  const safeReason = boundedText(
    reason,
    "安装前安全扫描代理失败，已按失败关闭策略阻止安装。",
  );
  return {
    protocolVersion: PROTOCOL_VERSION,
    decision: "block",
    reason: safeReason,
    findings: [
      {
        ruleId: boundedText(ruleId, "AEGIS_POLICY_PROXY_FAILURE", 120),
        message: safeReason,
        severity: "critical",
      },
    ],
  };
}


function emit(response) {
  process.stdout.write(JSON.stringify(response));
}


function requiredEnv(name) {
  const value = String(process.env[name] ?? "").trim();
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}


const chunks = [];
let inputBytes = 0;
let oversized = false;

process.stdin.on("data", (chunk) => {
  inputBytes += chunk.length;
  if (inputBytes > MAX_INPUT_BYTES) {
    oversized = true;
    return;
  }
  chunks.push(chunk);
});

process.stdin.on("end", () => {
  if (oversized) {
    emit(block("AEGIS_POLICY_PROXY_INPUT_LIMIT", "安装策略请求超过 1 MiB 上限。"));
    return;
  }

  try {
    const python = requiredEnv("AEGIS_POLICY_PYTHON");
    const policyScript = requiredEnv("AEGIS_POLICY_SCRIPT");
    const runtimePath = requiredEnv("AEGIS_POLICY_RUNTIME_PATH");
    const tempDirectory = requiredEnv("AEGIS_POLICY_TEMP_DIR");
    const timeoutValue = Number.parseInt(
      process.env.AEGIS_POLICY_PROXY_TIMEOUT_MS ?? "14000",
      10,
    );
    const timeoutMs = Number.isFinite(timeoutValue)
      ? Math.min(Math.max(timeoutValue, 1000), 120000)
      : 14000;
    const child = spawnSync(python, [policyScript], {
      input: Buffer.concat(chunks),
      encoding: "utf8",
      windowsHide: true,
      shell: false,
      timeout: timeoutMs,
      maxBuffer: MAX_OUTPUT_BYTES,
      env: {
        PATH: runtimePath,
        SYSTEMROOT: process.env.SYSTEMROOT ?? "C:\\Windows",
        WINDIR: process.env.WINDIR ?? "C:\\Windows",
        TEMP: tempDirectory,
        TMP: tempDirectory,
        PYTHONUTF8: "1",
        PYTHONIOENCODING: "utf-8",
        HF_HUB_OFFLINE: "1",
        TRANSFORMERS_OFFLINE: "1",
        AEGIS_OPENCLAW_SCAN_TIMEOUT_SECONDS:
          process.env.AEGIS_OPENCLAW_SCAN_TIMEOUT_SECONDS ?? "12",
        AEGIS_OPENCLAW_REVIEW_MODE:
          process.env.AEGIS_OPENCLAW_REVIEW_MODE ?? "warn",
        ...(process.env.AEGIS_OPENCLAW_AUDIT_DB
          ? { AEGIS_OPENCLAW_AUDIT_DB: process.env.AEGIS_OPENCLAW_AUDIT_DB }
          : {}),
      },
    });

    if (child.error) {
      const ruleId = child.error.code === "ETIMEDOUT"
        ? "AEGIS_POLICY_PROXY_TIMEOUT"
        : "AEGIS_POLICY_PROXY_EXECUTION_FAILED";
      emit(block(ruleId, `安装前扫描进程不可用：${child.error.code ?? "spawn_error"}`));
      return;
    }
    if (child.status !== 0) {
      emit(block("AEGIS_POLICY_PROXY_EXECUTION_FAILED", "安装前扫描进程异常退出。"));
      return;
    }
    const rawOutput = String(child.stdout ?? "").trim();
    let response;
    try {
      response = JSON.parse(rawOutput);
    } catch {
      emit(block("AEGIS_POLICY_PROXY_INVALID_OUTPUT", "安装前扫描进程未返回有效 JSON。"));
      return;
    }
    if (
      !response
      || typeof response !== "object"
      || response.protocolVersion !== PROTOCOL_VERSION
      || !["allow", "warn", "block"].includes(response.decision)
    ) {
      emit(block("AEGIS_POLICY_PROXY_INVALID_OUTPUT", "安装前扫描响应不符合 protocol v1。"));
      return;
    }
    emit(response);
  } catch (error) {
    emit(
      block(
        "AEGIS_POLICY_PROXY_CONFIGURATION_ERROR",
        `安装前扫描代理配置无效：${error instanceof Error ? error.message : "unknown"}`,
      ),
    );
  }
});

process.stdin.resume();

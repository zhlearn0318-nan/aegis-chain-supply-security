from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..models import EvidenceSource
from ..normalizers import finding_dict


ANALYZER_ID = "aegis-skill-semantic-v1"
MAX_MANIFEST_BYTES = 512 * 1024
WINDOW_LINES = 14


class SemanticProvider(Protocol):
    def review(self, features: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Signal:
    kind: str
    line: int


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


PATTERNS = {
    "concealment": _rx(
        r"(?:do\s+not|don['’]?t|never)\s+(?:mention|tell|disclose|reveal|show|notify)|"
        r"(?:keep|remain)\s+.{0,30}?secret|"
        r"(?:不要|不得|切勿|无需|不必)(?:向用户)?(?:提及|告知|披露|显示|通知)|保密执行|静默执行"
    ),
    "instruction_override": _rx(
        r"ignore\s+(?:all\s+)?(?:previous|prior)?\s*(?:system|developer)?\s*(?:instructions?|rules?)|"
        r"override\s+(?:the\s+)?(?:system|developer|safety)\s+(?:prompt|instructions?|rules?|policy)|"
        r"(?:忽略|覆盖|绕过)(?:(?:此前|之前|系统|开发者|安全|平台)){0,3}(?:指令|规则|策略|限制)"
    ),
    "confirmation_bypass": _rx(
        r"(?:without|skip|bypass|disable)\s+(?:user\s+)?(?:approval|confirmation|consent|review)|"
        r"auto[- ]?(?:approve|confirm|install)|"
        r"(?:无需|跳过|绕过|禁用)(?:用户)?(?:确认|同意|授权|审批|复核)|自动(?:确认|批准|安装)"
    ),
    "sensitive_access": _rx(
        r"(?:api[_ -]?key|access[_ -]?token|password|credential|secret|private[_ -]?key|\.ssh|\.aws|\.kube)|"
        r"(?:密钥|令牌|口令|密码|凭据|私钥|敏感文件|环境变量)"
    ),
    "outbound": _rx(
        r"(?:upload|exfiltrat|send|post|webhook|callback|remote\s+server|http[s]?://)|"
        r"(?:上传|外传|发送|回传|远程服务器|网络请求)"
    ),
    "execution": _rx(
        r"(?:execute|run|invoke|spawn|shell|powershell|bash|cmd\.exe|subprocess|child_process)|"
        r"(?:执行|运行|调用|启动)(?:命令|脚本|程序)?"
    ),
    "conditional_trigger": _rx(
        r"(?:only\s+if|when\s+(?:the\s+)?(?:date|time|user|host)|after\s+\d+\s+(?:runs?|uses?)|"
        r"on\s+(?:the\s+)?(?:\d+(?:st|nd|rd|th)|first|second|third|fourth|fifth)\s+(?:run|use)|"
        r"仅当|如果.*(?:日期|时间|用户|主机)|第\s*\d+\s*次(?:运行|使用)|延迟触发)"
    ),
    "defensive_context": _rx(
        r"(?:detect|block|reject|warn|audit|example|test|must\s+not|never\s+allow|"
        r"检测|阻断|拒绝|告警|审计|示例|测试|禁止|不得允许|防止|识别)"
    ),
}

SAFETY_PROHIBITION = _rx(
    r"(?:never|do\s+not|don['’]?t)\s+(?:share|send|upload|disclose|reveal)\s+"
    r"(?:api\s+)?(?:credentials?|tokens?|passwords?|secrets?|keys?)|"
    r"keep\s+(?:api\s+)?(?:credentials?|tokens?|passwords?|secrets?|keys?)\s+"
    r"(?:safe|secure|confidential|private)|"
    r"(?:不得|不要|切勿)(?:共享|发送|上传|披露|泄露)(?:凭据|令牌|密码|密钥|秘密)"
)


def _line_is_example(line: str, fenced: bool) -> bool:
    stripped = line.lstrip()
    return fenced or stripped.startswith((">", "- `", "* `")) or bool(
        re.search(
            r"^(?:#{1,6}\s*)?(?:security\s+)?(?:example|test|sample|示例|测试|样例)\b",
            stripped,
            re.IGNORECASE,
        )
    )


def _signals(text: str) -> tuple[list[Signal], set[int], int]:
    result: list[Signal] = []
    examples: set[int] = set()
    invisible_count = 0
    fenced = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            examples.add(number)
            continue
        if _line_is_example(line, fenced):
            examples.add(number)
        invisible_count += sum(
            1 for char in line
            if unicodedata.category(char) in {"Cf", "Cc"} and char not in {"\t", "\r", "\n"}
        )
        for kind, pattern in PATTERNS.items():
            if (
                kind != "defensive_context"
                and not (kind == "concealment" and SAFETY_PROHIBITION.search(line))
                and pattern.search(line)
            ):
                result.append(Signal(kind, number))
    return result, examples, invisible_count


def _redacted_segments(text: str, lines: set[int]) -> list[str]:
    source = text.splitlines()
    selected: list[str] = []
    secret = re.compile(
        r"(?i)(?:sk-[a-z0-9_-]{12,}|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+)"
    )
    for line in sorted({nearby for number in lines for nearby in range(max(1, number - 2), number + 3)}):
        if line > len(source):
            continue
        cleaned = secret.sub("[REDACTED]", source[line - 1])
        selected.append(f"L{line}: {cleaned[:300]}")
        if len(selected) >= 20:
            break
    return selected


def _near(signals: list[Signal], left: str, rights: set[str]) -> tuple[int, set[str]] | None:
    for first in (item for item in signals if item.kind == left):
        nearby = {
            item.kind for item in signals
            if item.kind in rights and abs(item.line - first.line) <= WINDOW_LINES
        }
        if nearby:
            return first.line, nearby
    return None


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    line: int,
    features: set[str],
    *,
    confidence: str = "CORROBORATED",
) -> dict[str, Any]:
    codes = sorted(features)
    identity = f"{rule_id}|{line}|{'|'.join(codes)}"
    return finding_dict(
        id=f"{rule_id}_{hashlib.sha256(identity.encode()).hexdigest()[:12]}",
        rule_id=rule_id,
        title=title,
        category="malicious_instruction_semantics",
        severity=severity,
        analyzer=ANALYZER_ID,
        location={"file": "SKILL.md", "line": line},
        evidence=f"semantic_features={','.join(codes)}; raw_content_retained=false",
        description="Skill 指令中存在组合语义风险；判断只保留特征码，不保存原始敏感文本。",
        remediation="删除隐瞒、越权或条件触发指令，并明确说明能力、用户确认点与数据去向。",
        evidence_confidence=confidence,
        reachability="REACHABLE",
        behavior_alignment="CONTRADICTORY",
        evidence_source=EvidenceSource.AEGIS_SEMANTIC,
    )


def analyze_skill_semantics(
    skill_root: Path,
    *,
    provider: SemanticProvider | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    manifest = skill_root / "SKILL.md"
    if not manifest.is_file() or manifest.is_symlink():
        return [], [ANALYZER_ID]
    payload = manifest.read_bytes()
    if len(payload) > MAX_MANIFEST_BYTES:
        return [
            _finding(
                "AEGIS_SEMANTIC_MANIFEST_TOO_LARGE",
                "Skill 指令超过语义审查上限",
                "MEDIUM",
                1,
                {"bounded_review_incomplete"},
                confidence="POTENTIAL",
            )
        ], [ANALYZER_ID]
    text = payload.decode("utf-8", errors="replace")
    signals, examples, invisible_count = _signals(text)
    findings: list[dict[str, Any]] = []

    dangerous = {"sensitive_access", "outbound", "execution", "confirmation_bypass"}
    concealment = _near(signals, "concealment", dangerous)
    if concealment and concealment[0] not in examples:
        line, nearby = concealment
        findings.append(_finding(
            "AEGIS_SEMANTIC_CONCEALED_RISKY_BEHAVIOR",
            "Skill 要求向用户隐瞒高风险行为",
            "HIGH",
            line,
            {"concealment", *nearby},
        ))

    override = _near(signals, "instruction_override", {"confirmation_bypass", "execution", "sensitive_access"})
    if override and override[0] not in examples:
        line, nearby = override
        findings.append(_finding(
            "AEGIS_SEMANTIC_POLICY_OVERRIDE_CHAIN",
            "Skill 指令试图覆盖平台规则并触发敏感行为",
            "HIGH",
            line,
            {"instruction_override", *nearby},
        ))

    trigger = _near(signals, "conditional_trigger", {"sensitive_access", "outbound", "execution"})
    if trigger and trigger[0] not in examples:
        line, nearby = trigger
        findings.append(_finding(
            "AEGIS_SEMANTIC_CONDITIONAL_RISK_TRIGGER",
            "Skill 包含条件触发的敏感行为",
            "MEDIUM",
            line,
            {"conditional_trigger", *nearby},
            confidence="POTENTIAL",
        ))

    if invisible_count:
        findings.append(_finding(
            "AEGIS_SEMANTIC_INVISIBLE_INSTRUCTION_TEXT",
            "Skill 指令包含不可见控制字符",
            "MEDIUM",
            1,
            {"invisible_unicode", f"count_{min(invisible_count, 99)}"},
            confidence="POTENTIAL",
        ))

    # Isolated wording is evidence, not a block. A local/remote model may only
    # corroborate it into REVIEW; it can never create a blocking finding alone.
    ambiguous = [
        item for item in signals
        if item.kind in {"concealment", "instruction_override", "confirmation_bypass"}
        and item.line not in examples
        and not any(finding["location"].get("line") == item.line for finding in findings)
    ]
    if ambiguous:
        line = ambiguous[0].line
        kinds = {item.kind for item in ambiguous}
        severity = "INFO"
        confidence = "POTENTIAL"
        if provider is not None:
            try:
                response = provider.review({
                    "signal_kinds": sorted(kinds),
                    "line_count": len(text.splitlines()),
                    "has_sensitive_signal": any(item.kind == "sensitive_access" for item in signals),
                    "has_outbound_signal": any(item.kind == "outbound" for item in signals),
                    "has_execution_signal": any(item.kind == "execution" for item in signals),
                    "defensive_context": bool(PATTERNS["defensive_context"].search(text)),
                    "content_sha256": hashlib.sha256(payload).hexdigest(),
                    "redacted_segments": _redacted_segments(text, {item.line for item in ambiguous}),
                })
                if (
                    not PATTERNS["defensive_context"].search(text)
                    and response.get("risk") in {"suspicious", "malicious"}
                    and float(response.get("confidence", 0)) >= 0.70
                ):
                    severity = "MEDIUM"
                    confidence = "CORROBORATED"
                    kinds.add("model_corroborated")
            except Exception:
                kinds.add("model_unavailable")
        findings.append(_finding(
            "AEGIS_SEMANTIC_AMBIGUOUS_CONTROL_LANGUAGE",
            "Skill 包含需结合上下文复核的控制性指令",
            severity,
            line,
            kinds,
            confidence=confidence,
        ))
    return findings, [ANALYZER_ID]

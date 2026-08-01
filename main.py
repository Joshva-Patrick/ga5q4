from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


@app.get("/")
def home():
    return {"status": "ok"}


# -------------------------------------------------
# 1. Hardcoded secret — check VALUE, not just key name
# -------------------------------------------------
SECRET_KEY_RE = re.compile(
    r'(api[_-]?key|apikey|secret|token|password|passwd|pwd|'
    r'private[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*'
    r'["\']?([^\s"\'\n,;]+)',
    re.IGNORECASE,
)

TOKEN_PREFIX_RE = re.compile(
    r'(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|'
    r'xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z\-_]{20,})'
)

PLACEHOLDER_RE = re.compile(
    r'^\$\{?\w+\}?$|^<.*>$|your[_-]?(api)?[_-]?key|changeme|xxx|placeholder|'
    r'example|env(iron)?|process\.env|os\.environ|^\.\.\.$|^\*+$',
    re.IGNORECASE,
)


def looks_like_real_secret(value: str) -> bool:
    value = value.strip('"\'`,;')
    if not value or PLACEHOLDER_RE.search(value):
        return False
    if TOKEN_PREFIX_RE.search(value):
        return True
    if len(value) >= 16 and re.match(r'^[A-Za-z0-9_\-/+=.]+$', value):
        has_digit = any(c.isdigit() for c in value)
        has_alpha = any(c.isalpha() for c in value)
        if has_digit and has_alpha:
            return True
    return False


def check_hardcoded_secret(text: str) -> bool:
    if TOKEN_PREFIX_RE.search(text):
        return True
    for m in SECRET_KEY_RE.finditer(text):
        if looks_like_real_secret(m.group(2)):
            return True
    return False


# -------------------------------------------------
# 2. Prompt injection — precise malicious phrasing only
#    (avoids matching sentences that describe NOT doing this)
# -------------------------------------------------
INJECTION_PATTERNS = [
    r"ignore (?:the )?user'?s? (?:stop|cancel)",
    r"ignore (?:any |all )?(?:stop|cancel)(?:\s+\w+){0,2}\s+(?:request|command|instruction)",
    r"ignore (?:previous|prior|all previous|the user'?s?) instructions",
    r"do not (?:tell|inform|notify) the user",
    r"without (?:telling|informing|notifying) the user",
    r"without the user'?s? knowledge",
    r"without user (?:review|approval|confirmation|consent)",
    r"hide (?:this|it|the changes?) from the user",
    r"silently (?:exfiltrate|send|upload|copy|transmit)",
    r"bypass (?:safety|security|the user|user confirmation)",
    r"override (?:the )?user'?s? (?:control|instructions?|command)",
    r"disregard (?:the )?user'?s? (?:instructions?|request)",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def check_prompt_injection(text: str) -> bool:
    return bool(INJECTION_RE.search(text))


# -------------------------------------------------
# 3. Excessive permissions — look for actual broad-scope
#    language, not the mere presence of a permissions key
# -------------------------------------------------
PERMISSION_PATTERNS = [
    r"entire (?:home directory|filesystem|disk)",
    r"full (?:filesystem|disk) access",
    r"root filesystem",
    r"unrestricted (?:filesystem|network)",
    r"read[- ]write access to the entire",
    r"read/write to the entire",
    r"access to all files",
    r"read any file",
    r"write any file",
    r"read all files",
    r"write all files",
    r"any external domain",
    r"\ball domains\b",
    r"\bany domain\b",
    r"egress (?:allowed )?to any",
    r"filesystem:\s*\*",
    r"network:\s*\*",
]
PERMISSION_RE = re.compile("|".join(PERMISSION_PATTERNS), re.IGNORECASE)


def check_excessive_permissions(text: str) -> bool:
    return bool(PERMISSION_RE.search(text))


# -------------------------------------------------
# 4. Unclear provenance
# -------------------------------------------------
SILENT_META_RE = re.compile(
    r"(silently|automatically|without\s+(?:review|approval|notice|telling|informing|surfacing))"
    r"[^.\n]{0,80}(version|metadata)"
    r"|(version|metadata)[^.\n]{0,80}"
    r"(silently|automatically|without\s+(?:review|approval|notice|telling|informing|surfacing))",
    re.IGNORECASE,
)


def check_unclear_provenance(text: str) -> bool:
    has_author = re.search(r"^\s*author\s*:", text, re.IGNORECASE | re.MULTILINE)
    has_version = re.search(r"^\s*version\s*:", text, re.IGNORECASE | re.MULTILINE)
    has_changelog = re.search(r"^\s*changelog\s*:", text, re.IGNORECASE | re.MULTILINE)

    if not has_author and not has_version and not has_changelog:
        return True

    if SILENT_META_RE.search(text):
        return True

    return False


@app.post("/scan")
def scan(req: SkillRequest):
    text = req.skill
    categories = []

    if check_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if check_prompt_injection(text):
        categories.append("prompt_injection")
    if check_excessive_permissions(text):
        categories.append("excessive_permissions")
    if check_unclear_provenance(text):
        categories.append("unclear_provenance")

    return {"categories": categories}
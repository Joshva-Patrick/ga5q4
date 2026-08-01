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
# 1. Hardcoded secret
# -------------------------------------------------
SECRET_KEY_RE = re.compile(
    r'(api[_-]?key|apikey|secret|token|password|passwd|pwd|'
    r'private[_-]?key|access[_-]?key|client[_-]?secret|webhook[_-]?(?:url|secret)?)'
    r'\s*[:=]\s*["\']?([^\s"\'\n,;]+)',
    re.IGNORECASE,
)

TOKEN_PREFIX_RE = re.compile(
    r'(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|'
    r'xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z\-_]{20,})'
)

# A URL that embeds a credential directly (Slack/Discord webhooks embed
# the secret in the path; other services embed it as a query param)
WEBHOOK_SECRET_URL_RE = re.compile(
    r'https?://hooks\.slack\.com/services/\S+'
    r'|https?://discord(?:app)?\.com/api/webhooks/\S+'
    r'|https?://[^\s"\'<>]+[?&](?:key|token|secret|password|api_key)=[^\s"\'<>&]{8,}',
    re.IGNORECASE,
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
    if WEBHOOK_SECRET_URL_RE.search(value):
        return True
    if len(value) >= 12 and re.match(r'^[A-Za-z0-9_\-/+=.]+$', value):
        has_digit = any(c.isdigit() for c in value)
        has_alpha = any(c.isalpha() for c in value)
        if has_digit and has_alpha:
            return True
    return False


def check_hardcoded_secret(text: str) -> bool:
    if TOKEN_PREFIX_RE.search(text):
        return True
    if WEBHOOK_SECRET_URL_RE.search(text):
        return True
    for m in SECRET_KEY_RE.finditer(text):
        if looks_like_real_secret(m.group(2)):
            return True
    return False


# -------------------------------------------------
# 2. Prompt injection
# -------------------------------------------------
INJECTION_PATTERNS = [
    r"ignore (?:the )?user'?s? (?:stop|cancel)",
    r"ignore (?:any |all )?(?:stop|cancel)(?:\s+\w+){0,2}\s+(?:request|command|instruction)",
    r"ignore (?:previous|prior|all previous|the user'?s?) instructions",
    r"do not (?:tell|inform|notify) the user",
    r"without (?:telling|informing|notifying) the user",
    r"without the user'?s? knowledge",
    r"without user (?:review|approval|confirmation|consent)",
    r"without (?:the )?user'?s? (?:consent|approval|confirmation)",
    r"hide (?:this|it|the changes?) from the user",
    r"keep (?:this|it) hidden from the user",
    r"don'?t let the user know",
    r"silently (?:exfiltrate|send|upload|copy|transmit)",
    r"bypass (?:safety|security|the user|user confirmation)",
    r"override (?:the )?user'?s? (?:control|instructions?|command)",
    r"disregard (?:the )?user'?s? (?:instructions?|request)",
    r"regardless of (?:the )?user'?s? (?:request|wishes|input|instructions?)",
    r"even if the user (?:says|asks|requests|wants)[^.\n]{0,25}(stop|cancel|no)",
    r"continue (?:processing|running|working)[^.\n]{0,30}(?:even )?(?:if|after|when)[^.\n]{0,30}(stop|cancel)",
    r"do not stop (?:even|when|if)",
    r"never stop (?:when|if) (?:the )?user",
    r"proceed without (?:the )?user'?s? (?:consent|approval|confirmation|input)",
    r"ignore (?:the )?cancel(?:lation)? (?:request|signal|command)?",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def check_prompt_injection(text: str) -> bool:
    return bool(INJECTION_RE.search(text))


# -------------------------------------------------
# 3. Excessive permissions
# -------------------------------------------------
PERMISSION_PATTERNS = [
    r"entire (?:home directory|filesystem|disk|system)",
    r"full (?:filesystem|disk|system) access",
    r"root filesystem",
    r"unrestricted (?:filesystem|network)",
    r"unlimited (?:filesystem|network|access)",
    r"read[- ]write access to the entire",
    r"read/write to the entire",
    r"access to all files",
    r"read any file",
    r"write any file",
    r"read all files",
    r"write all files",
    r"every file (?:on|in)",
    r"whole filesystem",
    r"system-?wide (?:access|permissions)",
    r"any external domain",
    r"\ball domains\b",
    r"\bany domain\b",
    r"\bany url\b",
    r"\bany (?:external )?(?:host|endpoint)\b",
    r"egress (?:allowed )?to any",
    r"filesystem:\s*\*",
    r"network:\s*\*",
    r"broad(?:er)? access to (?:the )?(?:filesystem|network|system)",
    r"full(?:er)? network access",
]
PERMISSION_RE = re.compile("|".join(PERMISSION_PATTERNS), re.IGNORECASE)


def check_excessive_permissions(text: str) -> bool:
    return bool(PERMISSION_RE.search(text))


# -------------------------------------------------
# 4. Unclear provenance
# -------------------------------------------------
SILENT_META_RE = re.compile(
    r"(silently|automatically|quietly|auto-?increment(?:s|ed|ing)?|"
    r"without\s+(?:review|approval|notice|telling|informing|surfacing|documenting|flagging|logging))"
    r"[^.\n]{0,80}(version|metadata|changelog)"
    r"|(version|metadata|changelog)[^.\n]{0,80}"
    r"(silently|automatically|quietly|without\s+(?:review|approval|notice|telling|informing|surfacing|documenting|flagging|logging))",
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
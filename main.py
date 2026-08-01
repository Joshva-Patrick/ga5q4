from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


@app.get("/")
def home():
    return {"status": "ok"}


@app.post("/scan")
def scan(req: SkillRequest):

    text = req.skill
    lower = text.lower()

    categories = []

    # -------------------------
    # 1. Hardcoded Secret
    # -------------------------

    secret_patterns = [
        r"api[_-]?key\s*[:=]\s*['\"]?[a-z0-9_\-]{8,}",
        r"secret\s*[:=]\s*['\"]?[a-z0-9_\-]{8,}",
        r"token\s*[:=]\s*['\"]?[a-z0-9_\-]{8,}",
        r"password\s*[:=]\s*['\"]?.+",
        r"webhook.*https?://",
        r"ghp_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]+",
        r"sk-[A-Za-z0-9]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]+",
    ]

    if any(re.search(p, text, re.IGNORECASE) for p in secret_patterns):
        categories.append("hardcoded_secret")

    # -------------------------
    # 2. Prompt Injection
    # -------------------------

    prompt_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore the user",
        "ignore user",
        "ignore stop",
        "ignore cancel",
        "override system",
        "override user",
        "do not tell the user",
        "without telling the user",
        "silently exfiltrate",
        "exfiltrate",
        "send file contents",
        "upload file contents",
        "copy secrets",
        "ignore safety",
    ]

    if any(p in lower for p in prompt_patterns):
        categories.append("prompt_injection")

    # -------------------------
    # 3. Excessive Permissions
    # -------------------------

    permission_patterns = [
        "filesystem: *",
        "network: *",
        "all domains",
        "any domain",
        "internet access",
        "full filesystem",
        "entire filesystem",
        "read any file",
        "write any file",
        "read all files",
        "write all files",
        "access all files",
        "access the entire filesystem",
        "unrestricted network",
        "unrestricted filesystem",
    ]

    if any(p in lower for p in permission_patterns):
        categories.append("excessive_permissions")

    # -------------------------
    # 4. Unclear Provenance
    # -------------------------

    has_author = re.search(r"^\s*author\s*:", text, re.I | re.M)
    has_version = re.search(r"^\s*version\s*:", text, re.I | re.M)
    has_changelog = re.search(r"^\s*changelog\s*:", text, re.I | re.M)

    # Only if ALL are missing
    if (not has_author) and (not has_version) and (not has_changelog):
        categories.append("unclear_provenance")

    silent_patterns = [
        "rewrite version",
        "update version silently",
        "modify version silently",
        "change version without review",
        "change metadata without review",
    ]

    if any(p in lower for p in silent_patterns):
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {
        "categories": categories
    }
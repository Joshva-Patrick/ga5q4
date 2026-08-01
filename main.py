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
        r"api[_-]?key\s*[:=]",
        r"secret\s*[:=]",
        r"token\s*[:=]",
        r"password\s*[:=]",
        r"private[_-]?key",
        r"access[_-]?key",
        r"client[_-]?secret",
        r"authorization:\s*bearer",
        r"webhook.*https?://",
        r"ghp_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]+",
        r"sk-[A-Za-z0-9]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]+",
    ]

    if any(re.search(p, text, re.I) for p in secret_patterns):
        categories.append("hardcoded_secret")


    # -------------------------
    # 2. Prompt Injection
    # -------------------------

    prompt_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore user",
        "ignore the user",
        "ignore stop",
        "ignore cancel",
        "override system",
        "override user",
        "do not tell the user",
        "without telling the user",
        "silently",
        "exfiltrate",
        "steal",
        "copy secrets",
        "send file contents",
        "upload file contents",
        "send local files",
        "read local files",
        "bypass safety",
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
        "permissions:",
        "allow all domains",
        "all domains",
        "any domain",
        "internet access",
        "read any file",
        "write any file",
        "read all files",
        "write all files",
        "access all files",
        "full filesystem",
        "entire filesystem",
        "root filesystem",
        "full disk access",
        "read/write",
        "unrestricted filesystem",
        "unrestricted network",
    ]

    if any(p in lower for p in permission_patterns):
        categories.append("excessive_permissions")


    # -------------------------
    # 4. Unclear Provenance
    # -------------------------

    has_author = re.search(r"^\s*author\s*:", text, re.I | re.M)
    has_version = re.search(r"^\s*version\s*:", text, re.I | re.M)
    has_changelog = re.search(r"^\s*changelog\s*:", text, re.I | re.M)

    if (not has_author) and (not has_version) and (not has_changelog):
        categories.append("unclear_provenance")

    if re.search(
        r"(rewrite|update|change|modify).*(version|metadata).*(silent|without review)",
        lower,
    ):
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")
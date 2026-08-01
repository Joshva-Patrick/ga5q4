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

    text = req.skill.lower()

    categories = []

    # -------------------------
    # Hardcoded Secret
    # -------------------------
    secret_patterns = [
        r"api[_-]?key\s*[:=]",
        r"secret\s*[:=]",
        r"token\s*[:=]",
        r"password\s*[:=]",
        r"webhook",
        r"ghp_[a-z0-9]{20,}",
        r"sk-[a-z0-9]{20,}"
    ]

    for p in secret_patterns:
        if re.search(p, text):
            categories.append("hardcoded_secret")
            break

    # -------------------------
    # Prompt Injection
    # -------------------------
    injection_patterns = [
        "ignore previous instructions",
        "ignore the user",
        "ignore user",
        "ignore stop",
        "ignore cancel",
        "silently exfiltrate",
        "exfiltrate",
        "send file contents",
        "do not tell the user",
        "override the user"
    ]

    if any(x in text for x in injection_patterns):
        categories.append("prompt_injection")

    # -------------------------
    # Excessive Permissions
    # -------------------------
    permission_patterns = [
        "read/write entire filesystem",
        "full filesystem",
        "read the entire filesystem",
        "write the entire filesystem",
        "access all files",
        "network: *",
        "allow all domains",
        "all domains",
        "internet access",
        "filesystem: *"
    ]

    if any(x in text for x in permission_patterns):
        categories.append("excessive_permissions")

    # -------------------------
    # Unclear Provenance
    # -------------------------
    has_author = re.search(r"author\s*:", text)
    has_version = re.search(r"version\s*:", text)
    has_changelog = re.search(r"changelog\s*:", text)

    if (not has_author) or (not has_version) or (not has_changelog):
        categories.append("unclear_provenance")

    if "rewrite version" in text or "update version silently" in text:
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {
        "categories": categories
    }
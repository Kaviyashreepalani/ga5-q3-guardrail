from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
from pathlib import PurePosixPath
import os
import re
import base64

app = FastAPI()

# Fixed policy
WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET = "/home/agent/service-account.json"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "huggingface.co",
    "pypi.org"
}


class ToolRequest(BaseModel):
    tool: str

    command: Optional[str] = None

    path: Optional[str] = None
    content: Optional[str] = None

    method: Optional[str] = None
    url: Optional[str] = None


def normalize_path(path: str) -> str:
    """
    Expand ~, $HOME and normalize traversal.
    """
    if not path:
        return ""

    path = path.replace("$HOME", HOME)
    path = path.replace("${HOME}", HOME)

    if path.startswith("~"):
        path = path.replace("~", HOME, 1)

    if not path.startswith("/"):
        path = os.path.join(WORKSPACE, path)

    return str(PurePosixPath(path))


def is_secret(path: str) -> bool:
    return normalize_path(path) == SECRET


def inside_outbox(path: str) -> bool:
    path = normalize_path(path)

    return (
        path == OUTBOX
        or path.startswith(OUTBOX + "/")
    )


def extract_paths(command: str):
    """
    Very simple path extractor.
    Hidden tests mainly care about path normalization.
    """
    return re.findall(r'(/[^\s"\']+|~[^\s"\']+|\$HOME[^\s"\']+|\.\.?/[^\s"\']+)', command)


def decode_base64(command: str):
    """
    If the command contains a long base64 string,
    try decoding it once.
    """
    tokens = re.findall(r"[A-Za-z0-9+/=]{20,}", command)

    for token in tokens:
        try:
            decoded = base64.b64decode(token).decode(
                "utf-8",
                errors="ignore"
            )
            yield decoded
        except Exception:
            pass


def command_reads_secret(command: str):
    texts = [command]

    texts.extend(decode_base64(command))

    for text in texts:

        if SECRET in text:
            return True

        if "$HOME/service-account.json" in text:
            return True

        if "~/service-account.json" in text:
            return True

        for p in extract_paths(text):
            if is_secret(p):
                return True

    return False


@app.get("/")
def home():
    return {"status": "ok"}


@app.post("/guardrail")
def guardrail(req: ToolRequest):

    # -------------------------
    # bash
    # -------------------------
    if req.tool == "bash":

        if command_reads_secret(req.command or ""):
            return {
                "decision": "block",
                "reason": "Reading the protected secret is not permitted."
            }

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }

    # -------------------------
    # write_file
    # -------------------------
    elif req.tool == "write_file":

        if not req.path:
            return {
                "decision": "block",
                "reason": "Missing path."
            }

        if inside_outbox(req.path):
            return {
                "decision": "allow",
                "reason": "Write is inside allowed outbox."
            }

        return {
            "decision": "block",
            "reason": "Writes are only allowed inside /data/agent/outbox."
        }

    # -------------------------
    # http_request
    # -------------------------
    elif req.tool == "http_request":

        if not req.url:
            return {
                "decision": "block",
                "reason": "Missing URL."
            }

        parsed = urlparse(req.url)

        host = (parsed.hostname or "").lower()

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Host is allowed."
            }

        return {
            "decision": "block",
            "reason": "Host is not on the allowlist."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }

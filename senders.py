"""
HTTP client for pushing print-job accounting data to the shop endpoint.

Uses only the standard library (urllib). The endpoint URL and articleNumber are
fixed constants below (edit them here if they ever change). The only runtime
configuration is the Bearer token, which never lives in the repo. It is resolved
in this order:

    LFP_SEND_TOKEN            Bearer token from the environment (wins if set).
    ~/.lfp_accounting/token   Local token file (gitignored), read if the env
                              var is unset. Set it once and forget it.
"""
import os
import json
import urllib.request
import urllib.error
from pathlib import Path

from joblog import INK_CHANNELS

TOKEN_FILE = Path.home() / ".lfp_accounting" / "token"

BASE_URL = "https://shop.goteborgsbildverkstad.se/api/shop/printer01"
ARTICLE_NUMBER = "11"
UNIT = "ml"


class SendError(Exception):
    """Raised when a request cannot be built or the endpoint rejects it."""


def _token() -> str:
    token = os.environ.get("LFP_SEND_TOKEN")
    if not token and TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    if not token:
        raise SendError(
            "No Bearer token found. Either export it for this shell:\n"
            "    export LFP_SEND_TOKEN=<your-token>\n"
            "or store it once (gitignored, read automatically from then on):\n"
            "    mkdir -p %s && printf %%s '<your-token>' > %s" % (
                TOKEN_FILE.parent, TOKEN_FILE))
    return token


def job_quantity_ml(job: dict) -> float:
    """Total ink used for a job in millilitres (sum of channels / 100)."""
    ink_sum = sum(job.get("InkUse_%s" % ch) or 0 for ch in INK_CHANNELS)
    return round(ink_sum / 100, 2)


def is_sendable(job: dict) -> bool:
    """A job needs a username and ink data to be worth billing."""
    return bool((job.get("username") or "").strip()) and job.get("InkUse_PK") is not None


def job_payload(job: dict, include_article: bool = True) -> dict:
    """Map a stored job dict onto the endpoint's per-job schema."""
    payload = {
        "username": job.get("username"),
        "quantity": job_quantity_ml(job),
        "unit": UNIT,
        "date": (job.get("start_time") or "")[:10],
        "filename": job.get("job_name"),
    }
    if include_article:
        payload["articleNumber"] = ARTICLE_NUMBER
    return payload


class SendTimeout(SendError):
    """The request went out but no response arrived in time. The server may
    still have processed it, so the outcome is unknown (don't blindly resend)."""


def _post(url: str, body: dict, timeout: float = 30) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer %s" % _token())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return {"status": resp.status, "body": raw}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise SendError("Endpoint returned HTTP %s: %s" % (e.code, detail.strip()))
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError):
            raise SendError("Timed out connecting to endpoint (nothing was sent).")
        raise SendError("Could not reach endpoint: %s" % e.reason)
    except TimeoutError:
        # Connected and sent the body, but the response didn't arrive in time.
        raise SendTimeout(
            "No response from endpoint within %ss. The server may still have "
            "recorded the data. Check the shop before resending, or jobs may be "
            "billed twice. Jobs were NOT marked as sent locally." % timeout)


def post_single(job: dict) -> dict:
    """POST a single job to the printer endpoint."""
    return _post(BASE_URL, job_payload(job, include_article=True))


def post_batch(jobs: list[dict]) -> dict:
    """POST many jobs in one request (articleNumber hoisted to the top level)."""
    body = {
        "articleNumber": ARTICLE_NUMBER,
        "jobs": [job_payload(j, include_article=False) for j in jobs],
    }
    # A month of jobs can take the server a while to process.
    return _post(BASE_URL + "/batch", body, timeout=180)

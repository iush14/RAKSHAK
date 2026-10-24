import time
import requests
from dotenv import load_dotenv
import os


load_dotenv()


ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")
API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
MODEL = os.getenv(
    "CLOUDFLARE_AI_MODEL",
    "@cf/meta/llama-3.2-3b-instruct",
)


URL = (
    f"https://api.cloudflare.com/client/v4/accounts/"
    f"{ACCOUNT_ID}/ai/run/{MODEL}"
)


headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json",
}


prompt = """
Analyze this vulnerability in one short sentence:

CVE-2026-54371:
attr before version 2.6.0 contains a symlink traversal
vulnerability in getfattr and setfattr that allows local
privilege escalation.

Return only the sentence.
"""


payload = {
    "prompt": prompt,
    "max_tokens": 64,
}


print("Testing Cloudflare AI speed...")
print(f"Model: {MODEL}")
print()


start = time.perf_counter()

try:

    response = requests.post(
        URL,
        headers=headers,
        json=payload,
        timeout=180,
    )

    received = time.perf_counter()

    print(
        f"HTTP response received in: "
        f"{received - start:.2f} seconds"
    )

    response.raise_for_status()

    data = response.json()

    finished = time.perf_counter()

    print(
        f"JSON processed in: "
        f"{finished - received:.2f} seconds"
    )

    print(
        f"TOTAL TIME: "
        f"{finished - start:.2f} seconds"
    )

    print()
    print("RESPONSE:")
    print(data)

except Exception as exc:

    elapsed = time.perf_counter() - start

    print(
        f"FAILED after {elapsed:.2f} seconds"
    )

    print(
        type(exc).__name__,
        str(exc),
    )
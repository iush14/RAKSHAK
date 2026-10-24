from app.cloudflare_ai_client import analyze_with_cloudflare
import time


def main():
    print("Testing Cloudflare AI with real Rakshak finding...\n")

    finding = {
        "vulnerability_id": "CVE-2026-54371",
        "title": (
            "CVE-2026-54371: attr: attr: Symlink Traversal "
            "Privilege Escalation via getfattr and setfattr"
        ),
        "description": (
            "attr before version 2.6.0 contains a symlink traversal "
            "vulnerability in the getfattr and setfattr utilities "
            "that allows local attackers to escalate privileges by "
            "replacing a pathname component with a symbolic link "
            "during directory hierarchy traversal. Attackers who "
            "control a pathname component can redirect getfattr and "
            "setfattr operations to arbitrary files by substituting "
            "a symlink, leading to local privilege escalation when "
            "getfattr or setfattr is invoked by a privileged process "
            "over an attacker-controlled path."
        ),
        "severity": "MEDIUM",
        "priority": "MEDIUM",
        "risk_score": 42,
        "exploitability": 0.63,
        "affected_packages": ["libattr1"],
        "fixed_version": "",
        "production": True,
    }

    print("CVE:", finding["vulnerability_id"])
    print("Package:", finding["affected_packages"])
    print("Severity:", finding["severity"])
    print("Risk Score:", finding["risk_score"])
    print("\nSending request...\n")

    start = time.time()

    try:
        result = analyze_with_cloudflare(finding)

        elapsed = time.time() - start

        print("=" * 60)
        print(f"SECONDS: {elapsed:.2f}")
        print("=" * 60)

        print("\nCLOUDFLARE ANALYSIS:\n")

        for key, value in result.items():
            print(f"{key}:")
            print(value)
            print()

    except Exception as exc:

        elapsed = time.time() - start

        print("=" * 60)
        print(f"SECONDS: {elapsed:.2f}")
        print("=" * 60)

        print("\nERROR:")
        print(type(exc).__name__)
        print(str(exc))


if __name__ == "__main__":
    main()
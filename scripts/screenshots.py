"""Capture admin-UI screenshots for the README against a running stack.

Usage:
    uv run python scripts/screenshots.py \
        --email admin@example.com --password ... \
        --tenant <demo tenant id> --agent <agent id> --job <job id with tree>

Writes docs/screenshots/{dashboard,agents,agent-detail,job-tree}.png
"""

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).parent.parent / "docs" / "screenshots"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--job", required=True)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)

        page.goto(f"{args.base}/ui/login")
        page.fill("input[name=email]", args.email)
        page.fill("input[name=password]", args.password)
        # The SSO block below the password form has a submit button of its own,
        # so name the button rather than matching on type=submit. Waiting on the
        # settled page instead of a navigation event: login redirects twice
        # (/ui/login -> /ui -> /ui/t/{id}) and lands before a wait_for_url
        # registered after the click ever sees it.
        page.get_by_role("button", name="Sign in").click()
        page.wait_for_function("() => location.pathname.startsWith('/ui/t/')")

        shots = [
            (f"/ui/t/{args.tenant}", "dashboard.png", 1200),
            (f"/ui/t/{args.tenant}/agents", "agents.png", 300),
            (f"/ui/agents/{args.agent}", "agent-detail.png", 300),
            (f"/ui/jobs/{args.job}", "job-tree.png", 300),
        ]
        for path, name, settle_ms in shots:
            page.goto(f"{args.base}{path}")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(settle_ms)  # let charts animate in
            page.screenshot(path=str(OUT / name), full_page=(name != "dashboard.png"))
            print(f"captured {name}")

        browser.close()


if __name__ == "__main__":
    main()

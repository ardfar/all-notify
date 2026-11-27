"""Structured test result collection and Markdown/JSON reporting."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable


@dataclass
class CheckResult:
    id: str
    suite: str
    title: str
    status: str  # "PASS" | "FAIL" | "SKIP" | "WARN"
    duration_ms: int
    detail: str = ""
    evidence: dict = field(default_factory=dict)


class TestContext:
    """Shared runtime config & state passed across live E2E suites."""

    def __init__(
        self,
        *,
        run_id: str,
        server_url: str,
        phone_a: str | None,
        phone_b: str | None,
        admin_password: str | None,
        k_master: str | None,
        vps_ssh: str | None,
        interactive: bool,
        timeout_sec: float = 15.0,
    ) -> None:
        self.run_id = run_id
        self.server_url = server_url.rstrip("/")
        self.phone_a = phone_a
        self.phone_b = phone_b
        self.admin_password = admin_password
        self.k_master = k_master
        self.vps_ssh = vps_ssh
        self.interactive = interactive
        self.timeout_sec = timeout_sec

        self.results: list[CheckResult] = []
        # Test markers posted during the run (used by zero-knowledge audit).
        self.posted_markers: list[str] = []
        # Discovered runtime metadata (never includes secrets).
        self.meta: dict = {}

    def record(
        self,
        check_id: str,
        suite: str,
        title: str,
        fn: Callable[[], tuple[str, str, dict] | str | None],
    ) -> CheckResult:
        t0 = time.monotonic()
        try:
            out = fn()
            if out is None:
                status, detail, evidence = "PASS", "ok", {}
            elif isinstance(out, str):
                status, detail, evidence = "PASS", out, {}
            else:
                status, detail, evidence = out
        except SkipCheck as exc:
            status, detail, evidence = "SKIP", str(exc), {}
        except AssertionError as exc:
            status, detail, evidence = "FAIL", str(exc), {}
        except Exception as exc:  # noqa: BLE001
            status, detail, evidence = "FAIL", f"{type(exc).__name__}: {exc}", {}

        dur = int((time.monotonic() - t0) * 1000)
        res = CheckResult(
            id=check_id,
            suite=suite,
            title=title,
            status=status,
            duration_ms=dur,
            detail=detail,
            evidence=evidence,
        )
        self.results.append(res)
        icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️", "WARN": "⚠️"}.get(status, "•")
        print(f"  {icon} [{check_id}] {title} ({dur}ms) — {detail}")
        return res

    def summary_counts(self) -> dict[str, int]:
        counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "WARN": 0}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    def write_reports(self, out_dir: Path) -> tuple[Path, Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"live_e2e_{self.run_id}.json"
        md_path = out_dir / f"live_e2e_{self.run_id}.md"

        payload = {
            "run_id": self.run_id,
            "server_url": self.server_url,
            "phone_a": self.phone_a,
            "phone_b": self.phone_b,
            "counts": self.summary_counts(),
            "meta": self.meta,
            "results": [asdict(r) for r in self.results],
        }
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        counts = self.summary_counts()
        lines = [
            f"# All-Notify Live E2E Verification Report (`{self.run_id}`)",
            "",
            f"- **Server**: `{self.server_url}`",
            f"- **Phone A**: `{self.phone_a or 'none'}`",
            f"- **Phone B**: `{self.phone_b or 'none'}`",
            f"- **Totals**: ✅ {counts['PASS']} passed · ❌ {counts['FAIL']} failed · ⚠️ {counts['WARN']} warn · ⏭️ {counts['SKIP']} skipped",
            "",
            "| ID | Suite | Check | Status | Time | Detail |",
            "| :--- | :--- | :--- | :---: | ---: | :--- |",
        ]
        for r in self.results:
            icon = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "SKIP": "⏭️ SKIP", "WARN": "⚠️ WARN"}.get(
                r.status, r.status
            )
            detail_clean = r.detail.replace("\n", " ").replace("|", "\\|")
            lines.append(
                f"| `{r.id}` | {r.suite} | {r.title} | {icon} | {r.duration_ms}ms | {detail_clean} |"
            )
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return json_path, md_path


class SkipCheck(Exception):
    """Raised by a check when a prerequisite (e.g. second phone) is not attached."""


def wait_until(
    predicate: Callable[[], object],
    timeout_sec: float = 15.0,
    interval_sec: float = 0.25,
):
    """Poll predicate until it returns a truthy value or timeout expires."""
    deadline = time.monotonic() + timeout_sec
    last_val = None
    while time.monotonic() < deadline:
        last_val = predicate()
        if last_val:
            return last_val
        time.sleep(interval_sec)
    return last_val

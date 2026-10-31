"""Streamlit UI: upload a codebase, follow the scan, review exploits and patches.

Run from the repo root:
    MOCK_API=1 uv run --extra ui streamlit run ui/app.py      # no backend needed
    API_URL=http://localhost:8000 uv run --extra ui streamlit run ui/app.py
"""

import io
import os
import re
import zipfile
from typing import Any

import streamlit as st
from client import (
    FINAL_STATUSES,
    PIPELINE_STEPS,
    STATUS_LABELS,
    ApiClient,
    BackendError,
    Client,
)
from fake_backend import MockClient

API_URL = os.environ.get("API_URL", "http://localhost:8000")
MOCK_API = os.environ.get("MOCK_API") == "1"
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "50"))
POLL_SECONDS = 2.0

MARKDOWN_SPECIAL = set("\\`*_{}[]()#+-.!|<>~$")


def plain(text: str) -> str:
    """Escape Markdown so model output shows as text, never as links/images/HTML.

    Findings are generated from the uploaded code, so they are untrusted.
    """
    return "".join("\\" + c if c in MARKDOWN_SPECIAL else c for c in str(text))


def safe_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(text))[:50] or "finding"


@st.cache_resource
def get_client() -> Client:
    return MockClient() if MOCK_API else ApiClient(API_URL)


def zip_summary(data: bytes) -> tuple[int, int] | None:
    """Return (file count, unpacked bytes) from the zip's index, or None if invalid.

    Only reads the index; nothing is extracted in the UI.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            files = [i for i in zf.infolist() if not i.is_dir()]
    except zipfile.BadZipFile:
        return None
    return len(files), sum(i.file_size for i in files)


def reset() -> None:
    for key in ("job_id", "results"):
        st.session_state.pop(key, None)


def upload_view(client: Client) -> None:
    st.write(
        "Upload a `.zip` of a codebase you own. It is scanned for exploitable "
        "vulnerabilities, and each finding comes with a proposed fix."
    )
    upload = st.file_uploader("Codebase (.zip)", type="zip")
    if upload is None:
        return

    data = upload.getvalue()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        st.error(f"That file is larger than the {MAX_UPLOAD_MB} MB limit.")
        return
    summary = zip_summary(data)
    if summary is None:
        st.error("That file isn't a valid .zip archive.")
        return
    count, size = summary
    st.caption(f"{count} files, {size / 1_000_000:.1f} MB unpacked")

    confirmed = st.checkbox(
        "I own this code or have the right to scan it, and it is MIT licensed."
    )
    if st.button("Scan for exploits", type="primary", disabled=not confirmed):
        try:
            st.session_state.job_id = client.submit(upload.name, data)
        except BackendError as e:
            st.error(str(e))
            return
        st.rerun()


@st.fragment(run_every=POLL_SECONDS)
def progress_fragment(client: Client, job_id: str) -> None:
    """Re-runs on its own every POLL_SECONDS until the job finishes."""
    try:
        status = client.status(job_id)["status"]
    except BackendError as e:
        st.error(str(e))
        return
    if status in FINAL_STATUSES:
        st.rerun()  # full rerun so progress_view shows the final state
    step = PIPELINE_STEPS.index(status) if status in PIPELINE_STEPS else 0
    label = STATUS_LABELS.get(status, status)
    st.progress(step / (len(PIPELINE_STEPS) - 1), text=f"{label}…")
    st.caption("Scans can take several minutes. You can leave this tab open.")


def progress_view(client: Client, job_id: str) -> None:
    try:
        state = client.status(job_id)
    except BackendError as e:
        st.error(str(e))
        st.button("Start over", on_click=reset)
        return

    status = state["status"]
    label = STATUS_LABELS.get(status, status)

    if status not in FINAL_STATUSES:
        progress_fragment(client, job_id)
    elif status == "done":
        if "results" not in st.session_state:
            try:
                st.session_state.results = client.results(job_id)
            except BackendError as e:
                st.error(str(e))
                return
        results_view(client, job_id, st.session_state.results)
    else:
        message = label
        if state.get("detail"):
            message += f": {plain(state['detail'])}"
        st.error(message)
        st.button("Scan another codebase", on_click=reset)


def finding_view(finding: dict[str, Any]) -> None:
    header = (
        f"{plain(finding['title'])} · {plain(finding['cwe'])} · "
        f"{plain(finding['file'])}:{finding['line']}"
    )
    with st.expander(header, expanded=True):
        st.markdown("**Exploit**")
        st.markdown(plain(finding["explanation"]))
        st.markdown("**How it can be triggered**")
        st.code(finding["trigger"], language=None, wrap_lines=True)

        st.markdown("**Proposed fix**")
        patch = finding.get("patch")
        if patch:
            st.code(patch, language="diff")
            st.download_button(
                "Download patch",
                patch,
                file_name=f"{safe_filename(finding['id'])}.patch",
                mime="text/x-diff",
                key=f"download-{finding['id']}",
            )
        else:
            st.warning("No patch proposed. This one needs a manual fix.")


def results_view(client: Client, job_id: str, results: dict[str, Any]) -> None:
    findings = results["findings"]
    st.caption(
        f"Scanned {results['files_scanned']} files · backend: "
        f"{plain(results['backend'])}"
    )

    if not findings:
        st.success("No exploitable vulnerabilities found.")
    else:
        st.subheader(f"{len(findings)} potential exploit(s) found")
        st.info(
            "Patches are suggestions. Review each one, then apply it in your "
            "repo with `git apply <file>.patch`."
        )
        patches = [f["patch"] for f in findings if f.get("patch")]
        if patches:
            st.download_button(
                f"Download all {len(patches)} patches",
                "\n".join(patches),
                file_name="all-fixes.patch",
                mime="text/x-diff",
            )
        for finding in findings:
            finding_view(finding)

    st.divider()
    left, right = st.columns(2)
    if left.button("Delete my code and results"):
        try:
            client.delete(job_id)
        except BackendError as e:
            st.error(str(e))
            return
        reset()
        st.rerun()
    right.button("Scan another codebase", on_click=reset)


def main() -> None:
    st.set_page_config(page_title="Vulnerability Hunter", page_icon="🛡️")
    st.title("Vulnerability Hunter")

    client = get_client()
    with st.sidebar:
        st.markdown("**Backend**")
        if MOCK_API:
            st.warning("Mock mode: results are fake sample data.")
        elif client.health():
            st.success(f"Connected to {API_URL}")
        else:
            st.error(f"Can't reach {API_URL}")

    job_id = st.session_state.get("job_id")
    if job_id is None:
        upload_view(client)
    else:
        progress_view(client, job_id)


main()

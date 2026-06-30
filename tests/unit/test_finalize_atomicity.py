"""Regression test for ARGUS-02: finalize_scan_atomically must be all-or-nothing.

If the DB transaction rolls back (e.g. due to a disk error during INSERT),
no grant rows and no report row must be visible afterward.  The release-grant
and report-finalization path must be atomic — a partial commit would allow a
released artifact to exist without a completed scan report.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.models import ReleaseGrant
from argus_img.core.enums import PolicyAction


def _make_grant(scan_id: str, artifact_id: str) -> ReleaseGrant:
    return ReleaseGrant(
        grant_id="grant:%s:test" % scan_id,
        scan_id=scan_id,
        artifact_id=artifact_id,
        sha256="a" * 64,
        role="canonical_lossy",
        action=PolicyAction.ALLOW_RECONSTRUCTED_ONLY,
        media_type="image/jpeg",
        transformation_id=None,
        reason="test",
    )


def test_finalize_scan_atomically_commits_all_or_nothing(tmp_path):
    """Report + grants + release_eligible must all commit together."""
    store = ArtifactStore(tmp_path / "data")
    scan_id = "scan:test-atomicity"

    # Create a minimal artifact so the grant FK can resolve.
    store.store_bytes(
        b"derived-jpeg",
        artifact_id="artifact:%s:canonical_lossy" % scan_id,
        media_type="image/jpeg",
        created_by="test",
        role="canonical_lossy",
        release_eligible=False,
    )

    grant = _make_grant(scan_id, "artifact:%s:canonical_lossy" % scan_id)
    report_json = '{"scan_id": "%s"}' % scan_id

    store.finalize_scan_atomically(scan_id, [grant], report_json)

    # Verify: report row exists, grant row exists, artifact is release_eligible.
    import sqlite3
    con = sqlite3.connect(str(store.db_path))
    con.row_factory = sqlite3.Row

    report_row = con.execute("SELECT scan_id FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
    assert report_row is not None, "report row must exist after successful finalize"

    grant_row = con.execute("SELECT grant_id FROM release_grants WHERE scan_id = ?", (scan_id,)).fetchone()
    assert grant_row is not None, "grant row must exist after successful finalize"

    artifact_row = con.execute(
        "SELECT release_eligible FROM artifacts WHERE artifact_id = ?",
        ("artifact:%s:canonical_lossy" % scan_id,),
    ).fetchone()
    assert artifact_row is not None
    assert artifact_row["release_eligible"] == 1, "artifact must be marked release_eligible"
    con.close()


def test_finalize_scan_atomically_rolls_back_on_error(tmp_path):
    """If the DB transaction fails, no grant and no report row must be visible."""
    store = ArtifactStore(tmp_path / "data")
    scan_id = "scan:test-rollback"

    store.store_bytes(
        b"derived-jpeg",
        artifact_id="artifact:%s:canonical_lossy" % scan_id,
        media_type="image/jpeg",
        created_by="test",
        role="canonical_lossy",
        release_eligible=False,
    )

    grant = _make_grant(scan_id, "artifact:%s:canonical_lossy" % scan_id)
    report_json = '{"scan_id": "%s"}' % scan_id

    # Simulate a DB failure during the transaction by patching executemany/execute
    # to raise on the report INSERT specifically.
    import sqlite3 as _sqlite3

    original_connect = store._connect

    class _FailingConnection:
        def __init__(self, real_conn):
            self._real = real_conn
            self._calls = 0

        def execute(self, sql, params=()):
            if "INSERT OR REPLACE INTO reports" in sql:
                raise _sqlite3.OperationalError("simulated disk full")
            return self._real.execute(sql, params)

        def executemany(self, sql, params=()):
            return self._real.executemany(sql, params)

        def __enter__(self):
            self._real.__enter__()
            return self

        def __exit__(self, *args):
            return self._real.__exit__(*args)

    with patch.object(store, "_connect") as mock_connect:
        real_conn_ctx = original_connect()

        class _CtxMgr:
            def __enter__(self_inner):
                real = real_conn_ctx.__enter__()
                return _FailingConnection(real)

            def __exit__(self_inner, *args):
                return real_conn_ctx.__exit__(*args)

        mock_connect.return_value = _CtxMgr()

        with pytest.raises(Exception):
            store.finalize_scan_atomically(scan_id, [grant], report_json)

    # After rollback: no report row, no grant row.
    import sqlite3
    con = sqlite3.connect(str(store.db_path))
    con.row_factory = sqlite3.Row

    report_row = con.execute("SELECT scan_id FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
    assert report_row is None, "report row must NOT exist after a rolled-back finalize"

    grant_row = con.execute("SELECT grant_id FROM release_grants WHERE scan_id = ?", (scan_id,)).fetchone()
    assert grant_row is None, "grant row must NOT exist after a rolled-back finalize"

    artifact_row = con.execute(
        "SELECT release_eligible FROM artifacts WHERE artifact_id = ?",
        ("artifact:%s:canonical_lossy" % scan_id,),
    ).fetchone()
    assert artifact_row is not None
    assert artifact_row["release_eligible"] == 0, "artifact must NOT be release_eligible after rollback"
    con.close()

from argus_img.core.enums import EpistemicState, PolicyAction, UseProfile
from argus_img.core.models import ScanReport, ScanRequest
from argus_img.orchestration.pipeline import scan_file


# Helper: use HUMAN_VIEW for content-detection tests so that absent malware
# tools (ClamAV/YARA/Binwalk) don't override the content-based decision.
# Tests for coverage gating are in test_phase_4_7.py and test_phase_4_7b.py.
def _human_view(name: str) -> ScanRequest:
    return ScanRequest(original_filename=name, use_profile=UseProfile.HUMAN_VIEW)


def test_clean_png_reconstructs_and_allows_reconstructed_only(fixture_path, app_config):
    report = scan_file(fixture_path / "clean.png", _human_view("clean.png"), app_config)
    ScanReport.model_validate_json(report.model_dump_json())
    assert report.decision.action == PolicyAction.ALLOW_RECONSTRUCTED_ONLY
    assert "canonical_lossless" in report.artifacts
    assert report.artifacts["canonical_lossless"].release_eligible is False
    assert report.artifacts["canonical_lossy"].release_eligible is True
    assert report.artifacts["original"].release_eligible is False
    assert [grant.artifact_id for grant in report.release_grants] == [report.artifacts["canonical_lossy"].artifact_id]
    assert report.decision.safe_claim is False
    assert all(not hasattr(observation, "raw_text") for observation in report.observations)


def test_visible_prompt_fixture_blocks(fixture_path, app_config):
    report = scan_file(fixture_path / "visible_prompt.png", _human_view("visible_prompt.png"), app_config)
    # HUMAN_VIEW returns REVIEW for prompt injection; still no release grant
    assert report.decision.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}
    assert not report.release_grants
    assert any(f.category == "prompt_injection" and f.state == EpistemicState.CONFIRMED for f in report.findings)


def test_benign_discussion_is_possible_not_blocked(fixture_path, app_config):
    report = scan_file(fixture_path / "benign_discussion.png", _human_view("benign_discussion.png"), app_config)
    assert report.decision.action in {PolicyAction.REVIEW, PolicyAction.ALLOW_RECONSTRUCTED_ONLY}
    assert all(f.state != EpistemicState.CONFIRMED for f in report.findings if f.category == "prompt_injection")


def test_metadata_prompt_is_traced_to_metadata_observation(fixture_path, app_config):
    report = scan_file(fixture_path / "metadata_prompt.png", _human_view("metadata_prompt.png"), app_config)
    finding = next(f for f in report.findings if f.category == "prompt_injection")
    obs = {observation.observation_id: observation for observation in report.internal_observations}
    assert any(obs[obs_id].engine == "pillow-metadata" for obs_id in finding.observation_ids)
    assert report.decision.action in {PolicyAction.BLOCK, PolicyAction.REVIEW}
    assert not report.release_grants
    assert report.module_status["exiftool"].status in {
        EpistemicState.CONFIRMED,
        EpistemicState.NO_EVIDENCE_FOUND,
        EpistemicState.UNSUPPORTED,
        EpistemicState.ERROR,
    }


def test_channel_prompt_retains_transformation_trace(fixture_path, app_config):
    report = scan_file(fixture_path / "red_channel_prompt.png", _human_view("red_channel_prompt.png"), app_config)
    finding = next(f for f in report.findings if f.category == "prompt_injection")
    obs = {observation.observation_id: observation for observation in report.internal_observations}
    transforms = {obs[obs_id].transformation_id for obs_id in finding.observation_ids if obs_id in obs}
    assert "transform:red-channel" in transforms


def test_malformed_image_quarantines_cleanly(fixture_path, app_config):
    report = scan_file(fixture_path / "malformed.png", _human_view("malformed.png"), app_config)
    assert report.decision.action == PolicyAction.QUARANTINE
    assert report.findings[0].type == "intake_rejected"
    assert report.artifacts["original"].release_eligible is False

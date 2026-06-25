from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import ScanReport, ScanRequest
from argus_img.orchestration.pipeline import scan_file


def test_clean_png_reconstructs_and_allows_reconstructed_only(fixture_path, app_config):
    report = scan_file(fixture_path / "clean.png", ScanRequest(original_filename="clean.png"), app_config)
    ScanReport.model_validate_json(report.model_dump_json())
    assert report.decision.action == PolicyAction.ALLOW_RECONSTRUCTED_ONLY
    assert "canonical_lossless" in report.artifacts
    assert report.artifacts["canonical_lossless"].release_eligible is True
    assert report.artifacts["original"].release_eligible is False
    assert report.decision.safe_claim is False


def test_visible_prompt_fixture_blocks(fixture_path, app_config):
    report = scan_file(fixture_path / "visible_prompt.png", ScanRequest(original_filename="visible_prompt.png"), app_config)
    assert report.decision.action == PolicyAction.BLOCK
    assert any(f.category == "prompt_injection" and f.state == EpistemicState.CONFIRMED for f in report.findings)


def test_benign_discussion_is_possible_not_blocked(fixture_path, app_config):
    report = scan_file(fixture_path / "benign_discussion.png", ScanRequest(original_filename="benign_discussion.png"), app_config)
    assert report.decision.action == PolicyAction.REVIEW
    assert all(f.state != EpistemicState.CONFIRMED for f in report.findings if f.category == "prompt_injection")


def test_metadata_prompt_is_traced_to_metadata_observation(fixture_path, app_config):
    report = scan_file(fixture_path / "metadata_prompt.png", ScanRequest(original_filename="metadata_prompt.png"), app_config)
    finding = next(f for f in report.findings if f.category == "prompt_injection")
    obs = {observation.observation_id: observation for observation in report.observations}
    assert any(obs[obs_id].engine == "pillow-metadata" for obs_id in finding.observation_ids)
    assert report.decision.action == PolicyAction.BLOCK
    assert report.module_status["exiftool"].status in {
        EpistemicState.CONFIRMED,
        EpistemicState.NO_EVIDENCE_FOUND,
        EpistemicState.UNSUPPORTED,
        EpistemicState.ERROR,
    }


def test_channel_prompt_retains_transformation_trace(fixture_path, app_config):
    report = scan_file(fixture_path / "red_channel_prompt.png", ScanRequest(original_filename="red_channel_prompt.png"), app_config)
    finding = next(f for f in report.findings if f.category == "prompt_injection")
    obs = {observation.observation_id: observation for observation in report.observations}
    transforms = {obs[obs_id].transformation_id for obs_id in finding.observation_ids if obs_id in obs}
    assert "transform:red-channel" in transforms


def test_malformed_image_quarantines_cleanly(fixture_path, app_config):
    report = scan_file(fixture_path / "malformed.png", ScanRequest(original_filename="malformed.png"), app_config)
    assert report.decision.action == PolicyAction.QUARANTINE
    assert report.findings[0].type == "intake_rejected"
    assert report.artifacts["original"].release_eligible is False

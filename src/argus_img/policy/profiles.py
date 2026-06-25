from pathlib import Path

from argus_img.core.enums import UseProfile


PROFILE_FILES = {
    UseProfile.ARCHIVE_ONLY: "archive-only.yaml",
    UseProfile.HUMAN_VIEW: "human-view.yaml",
    UseProfile.VLM_READ_ONLY: "vlm-read-only.yaml",
    UseProfile.RAG_INGESTION: "rag-ingestion.yaml",
    UseProfile.AGENT_WITH_TOOLS: "agent-with-tools.yaml",
    UseProfile.SECURITY_FORENSICS: "forensic.yaml",
    UseProfile.PUBLIC_REPUBLISHING: "human-view.yaml",
    UseProfile.OCR_EXTRACTION: "human-view.yaml",
}


def policy_path(profile: UseProfile) -> Path:
    return Path("config/policies") / PROFILE_FILES[profile]


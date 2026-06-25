from argus_img.core.enums import UseProfile


PROFILE_FILES = {
    UseProfile.ARCHIVE_ONLY: "archive-only.yaml",
    UseProfile.HUMAN_VIEW: "human-view.yaml",
    UseProfile.VLM_READ_ONLY: "vlm-read-only.yaml",
    UseProfile.RAG_INGESTION: "rag-ingestion.yaml",
    UseProfile.AGENT_WITH_TOOLS: "agent-with-tools.yaml",
    UseProfile.SECURITY_FORENSICS: "forensic.yaml",
    UseProfile.PUBLIC_REPUBLISHING: "public-republishing.yaml",
    UseProfile.OCR_EXTRACTION: "ocr-extraction.yaml",
}

def policy_relative_path(profile: UseProfile) -> tuple[str, str]:
    return ("policies", PROFILE_FILES[profile])

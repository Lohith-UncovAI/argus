from pydantic import BaseModel, ConfigDict, Field


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_input_bytes: int = Field(default=25_000_000, gt=0)
    max_pixels_per_frame: int = Field(default=50_000_000, gt=0)
    max_total_decoded_pixels: int = Field(default=150_000_000, gt=0)
    max_transformed_pixels: int = Field(default=300_000_000, gt=0)
    max_width: int = Field(default=16_384, gt=0)
    max_height: int = Field(default=16_384, gt=0)
    max_frames: int = Field(default=30, gt=0)
    max_artifacts: int = Field(default=200, gt=0)
    max_artifact_bytes: int = Field(default=250_000_000, gt=0)
    max_metadata_bytes: int = Field(default=5_000_000, gt=0)
    max_extracted_objects: int = Field(default=100, ge=0)
    max_extracted_total_bytes: int = Field(default=50_000_000, gt=0)
    max_recursive_depth: int = Field(default=3, ge=0)
    max_text_bytes_per_source: int = Field(default=100_000, gt=0)
    max_text_bytes: int = Field(default=2_000_000, gt=0)
    max_subprocess_output_bytes: int = Field(default=1_000_000, gt=0)
    parser_timeout_seconds: int = Field(default=10, gt=0)
    detector_timeout_seconds: int = Field(default=30, gt=0)
    full_scan_timeout_seconds: int = Field(default=120, gt=0)

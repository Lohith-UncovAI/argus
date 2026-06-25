from pydantic import BaseModel


class Limits(BaseModel):
    max_input_bytes: int = 25_000_000
    max_pixels_per_frame: int = 50_000_000
    max_total_decoded_pixels: int = 150_000_000
    max_width: int = 16_384
    max_height: int = 16_384
    max_frames: int = 30
    max_metadata_bytes: int = 5_000_000
    max_extracted_objects: int = 100
    max_extracted_total_bytes: int = 50_000_000
    max_recursive_depth: int = 3
    max_text_bytes_per_source: int = 100_000
    parser_timeout_seconds: int = 10
    detector_timeout_seconds: int = 30
    full_scan_timeout_seconds: int = 120


ALLOWED_RASTER_FORMATS = {"JPEG", "PNG", "WEBP", "GIF", "TIFF", "BMP"}
REJECTED_ACTIVE_FORMATS = {"SVG", "PDF", "POSTSCRIPT", "PSD", "UNKNOWN"}


def is_allowed_format(format_name: str) -> bool:
    return format_name.upper() in ALLOWED_RASTER_FORMATS


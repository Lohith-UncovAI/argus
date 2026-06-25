from PIL import ImageOps


def invert_grayscale(image):
    return ImageOps.invert(ImageOps.grayscale(image))


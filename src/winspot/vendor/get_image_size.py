"""
Module to get image size and metadata without using image library bindings.

Supports BMP, GIF, ICO, JPEG, PNG, and TIFF formats.

:Original work: Copyright (c) 2013 Paulo Scardine
:Modified work: Copyright (c) 2025 Volodymyr Horshenin
:License: This software is released under the [MIT](https://opensource.org/licenses/MIT) License.
"""

import argparse
import io
import json
import logging
import os
import struct
import sys
import typing
import warnings


class UnknownImageFormat(Exception):
    """Exception for unknown image formats."""

    pass


class Image:
    """Image metadata container."""

    def __init__(
        self,
        path: str | None,
        format: typing.Literal["BMP", "GIF", "ICO", "JPEG", "PNG", "TIFF"],
        file_size: int,
        width: int,
        height: int,
    ) -> None:

        self.path = path
        self.format = format
        self.file_size = file_size
        self.width = width
        self.height = height

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(
            {
                "path": self.path,
                "format": self.format,
                "file_size": self.file_size,
                "width": self.width,
                "height": self.height,
            },
            indent=indent,
        )

    def __str__(self) -> str:
        return f"Image\n-----\nPath: {self.path}\nFormat: {self.format}\nFile Size: {self.file_size} bytes\nWidth: {self.width}px\nHeight: {self.height}px"

    def __repr__(self) -> str:
        return f"Image(path={self.path}, format={self.format}, file_size={self.file_size}, width={self.width}, height={self.height})"


def get_image_size(file_path: str) -> tuple[int, int]:
    img: Image = get_image_metadata(file_path)
    return (img.width, img.height)


def try_get_image_size(file_path: str) -> tuple[int, int] | None:
    try:
        return get_image_size(file_path)
    except Exception:
        return None


def get_image_size_from_bytesio(
    input: io.BufferedReader, buffer_size: int
) -> tuple[int, int]:
    img: Image = get_image_metadata_from_bytesio(input, buffer_size)
    return (img.width, img.height)


def get_image_metadata(file_path: str) -> Image:
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as input:
        return get_image_metadata_from_bytesio(input, file_size, file_path)


def get_image_metadata_from_bytesio(
    input: io.BufferedReader, buffer_size: int, file_path: str | None = None
) -> Image:
    """
    Extracts image metadata from a file-like object.

    Args:
        input (io.BufferedReader): file-like object containing image data
        buffer_size (int): size of buffer in bytes
        file_path (str | None): optional file path for reference

    Returns:
        Image: Image metadata object
    """
    height: int = -1
    width: int = -1
    data: bytes = input.read(26)

    if (buffer_size >= 10) and data[:6] in (b"GIF87a", b"GIF89a"):
        # GIFs
        image_format = "GIF"
        width, height = map(int, struct.unpack("<HH", data[6:10]))
    elif (
        (buffer_size >= 24)
        and data.startswith(b"\211PNG\r\n\032\n")
        and (data[12:16] == b"IHDR")
    ):
        # PNGs
        image_format = "PNG"
        width, height = map(int, struct.unpack(">LL", data[16:24]))
    elif (buffer_size >= 16) and data.startswith(b"\211PNG\r\n\032\n"):
        # Older PNGs
        image_format = "PNG"
        width, height = map(int, struct.unpack(">LL", data[8:16]))
    elif (buffer_size >= 2) and data.startswith(b"\377\330"):
        # JPEG
        image_format = "JPEG"
        input.seek(0)
        input.read(2)
        b = input.read(1)
        while b and ord(b) != 0xDA:
            while ord(b) != 0xFF:
                b = input.read(1)
            while ord(b) == 0xFF:
                b = input.read(1)
            if ord(b) >= 0xC0 and ord(b) <= 0xC3:
                input.read(3)
                height, width = map(int, struct.unpack(">HH", input.read(4)))
                break
            else:
                input.read(int(struct.unpack(">H", input.read(2))[0]) - 2)
            b = input.read(1)
    elif (buffer_size >= 26) and data.startswith(b"BM"):
        # BMP
        image_format = "BMP"
        header_size = struct.unpack("<I", data[14:18])[0]
        if header_size == 12:
            width, height = map(int, struct.unpack("<HH", data[18:22]))
        elif header_size >= 40:
            width, height = map(int, struct.unpack("<ii", data[18:26]))
            height = abs(height)  # handle top-down bitmaps
        else:
            raise UnknownImageFormat(f"Unkown DIB header size: {header_size}")
    elif (buffer_size >= 8) and data[:4] in (b"II\052\000", b"MM\000\052"):
        # Standard TIFF, big- or little-endian
        # BigTIFF and other different but TIFF-like formats are not
        # supported currently
        image_format = "TIFF"
        byte_order = data[:2]
        bo_char = ">" if byte_order == b"MM" else "<"
        # maps TIFF type id to size (in bytes)
        # and python format char for struct
        tiff_types = {
            1: (1, bo_char + "B"),  # BYTE
            2: (1, bo_char + "c"),  # ASCII
            3: (2, bo_char + "H"),  # SHORT
            4: (4, bo_char + "L"),  # LONG
            5: (8, bo_char + "LL"),  # RATIONAL
            6: (1, bo_char + "b"),  # SBYTE
            7: (1, bo_char + "c"),  # UNDEFINED
            8: (2, bo_char + "h"),  # SSHORT
            9: (4, bo_char + "l"),  # SLONG
            10: (8, bo_char + "ll"),  # SRATIONAL
            11: (4, bo_char + "f"),  # FLOAT
            12: (8, bo_char + "d"),  # DOUBLE
        }
        ifd_offset = struct.unpack(bo_char + "L", data[4:8])[0]
        count_size = 2
        input.seek(ifd_offset)
        ec = input.read(count_size)
        ifd_entry_count = struct.unpack(bo_char + "H", ec)[0]
        # 2 bytes: TagId + 2 bytes: type + 4 bytes: count of values + 4
        # bytes: value offset
        ifd_entry_size = 12
        for i in range(ifd_entry_count):
            entry_offset = ifd_offset + count_size + i * ifd_entry_size
            input.seek(entry_offset)
            tag = input.read(2)
            tag = struct.unpack(bo_char + "H", tag)[0]
            if tag == 256 or tag == 257:
                # if type indicates that value fits into 4 bytes, value
                # offset is not an offset but value itself
                field_type = input.read(2)
                field_type = struct.unpack(bo_char + "H", field_type)[0]
                if field_type not in tiff_types:
                    raise UnknownImageFormat(f"Unkown TIFF field type: {field_type}")
                type_size = tiff_types[field_type][0]
                type_char = tiff_types[field_type][1]
                input.seek(entry_offset + 8)
                value = input.read(type_size)
                value = int(struct.unpack(type_char, value)[0])
                if tag == 256:
                    width = value
                else:
                    height = value
            if width > -1 and height > -1:
                break
    elif buffer_size >= 2:
        # http://en.wikipedia.org/wiki/ICO_(file_format)
        image_format = "ICO"
        input.seek(0)
        reserved = input.read(2)
        if 0 != struct.unpack("<H", reserved)[0]:
            raise UnknownImageFormat("File format not recognized")
        format = input.read(2)
        assert 1 == struct.unpack("<H", format)[0]
        num = input.read(2)
        num = struct.unpack("<H", num)[0]
        if num > 1:
            warnings.warn(
                "ICO File contains more than one image"
            )  # TODO: replace with logging
        # http://msdn.microsoft.com/en-us/library/ms997538.aspx
        w = input.read(1)
        h = input.read(1)
        width = ord(w)
        height = ord(h)
    else:
        raise UnknownImageFormat("File format not recognized")

    return Image(
        path=file_path,
        format=image_format,
        file_size=buffer_size,
        width=width,
        height=height,
    )


def main(argv: typing.Sequence[str] | None = None) -> int:
    """Print image metadata fields for the given file path."""

    parser = argparse.ArgumentParser(
        prog="get_image_size",
        description="Print metadata for the given image paths (without image library bindings).",
    )

    parser.add_argument("path", help="Path to image file")
    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--json-indent", type=int, default=None, help="Indentation level for JSON output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")

    args = parser.parse_args(argv)

    loglevel = logging.INFO
    if args.verbose:
        loglevel = logging.DEBUG
    elif args.quiet:
        loglevel = logging.ERROR
    logging.basicConfig(level=loglevel)

    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(loglevel)

    logger.debug(f"Passed arguments: {args._get_args()}")
    logger.debug(f"Passed keyword arguments: {args._get_kwargs()}")

    try:
        img = get_image_metadata(args.path)
        if args.json:
            print(img.to_json(indent=args.json_indent))
        else:
            print(img)
    except Exception as e:
        logger.exception(e)
        return -1
    return 0


if __name__ == "__main__":
    sys.exit(main())

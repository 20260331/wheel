"""
Wheel command-line utility.
"""

from __future__ import annotations

import argparse
import os
import sys
from argparse import ArgumentTypeError

from ..wheelfile import WheelError


def unpack_f(args: argparse.Namespace) -> None:
    from .unpack import unpack

    unpack(args.wheelfile, args.dest)


def pack_f(args: argparse.Namespace) -> None:
    from .pack import pack

    pack(args.directory, args.dest_dir, args.build_number, args.local_version)


def convert_f(args: argparse.Namespace) -> None:
    from .convert import convert

    convert(args.files, args.dest_dir, args.verbose)


def tags_f(args: argparse.Namespace) -> None:
    from .tags import tags

    names = (
        tags(
            wheel,
            args.python_tag,
            args.abi_tag,
            args.platform_tag,
            args.build,
            args.remove,
        )
        for wheel in args.wheel
    )

    for name in names:
        print(name)


def info_f(args: argparse.Namespace) -> None:
    from .info import info

    try:
        info(args.wheelfile, args.verbose)
    except FileNotFoundError as e:
        raise WheelError(str(e)) from e


def delta_f(args: argparse.Namespace) -> None:
    from .delta import make_delta

    print(
        make_delta(
            args.wheelfile,
            args.overlay,
            args.dest_dir,
            allow_version_change=args.allow_version_change,
        )
    )


def apply_delta_f(args: argparse.Namespace) -> None:
    from .delta import apply_delta

    print(apply_delta(args.wheelfile, args.delta, args.dest_dir))


def version_f(args: argparse.Namespace) -> None:
    from .. import __version__

    print(f"wheel {__version__}")


def parse_build_tag(build_tag: str) -> str:
    if build_tag and not build_tag[0].isdigit():
        raise ArgumentTypeError("build tag must begin with a digit")
    elif "-" in build_tag:
        raise ArgumentTypeError("invalid character ('-') in build tag")

    return build_tag


TAGS_HELP = """\
Make a new wheel with given tags. Any tags unspecified will remain the same.
Starting the tags with a "+" will append to the existing tags. Starting with a
"-" will remove a tag (use --option=-TAG syntax). Multiple tags can be
separated by ".". The original file will remain unless --remove is given.  The
output filename(s) will be displayed on stdout for further processing.
"""


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    s = p.add_subparsers(help="commands")

    unpack_parser = s.add_parser("unpack", help="Unpack wheel")
    unpack_parser.add_argument(
        "--dest", "-d", help="Destination directory", default="."
    )
    unpack_parser.add_argument("wheelfile", help="Wheel file")
    unpack_parser.set_defaults(func=unpack_f)

    repack_parser = s.add_parser("pack", help="Repack wheel")
    repack_parser.add_argument("directory", help="Root directory of the unpacked wheel")
    repack_parser.add_argument(
        "--dest-dir",
        "-d",
        default=os.path.curdir,
        help="Directory to store the wheel (default %(default)s)",
    )
    repack_parser.add_argument(
        "--build-number",
        type=parse_build_tag,
        help="Build tag to use in the wheel name",
    )
    repack_parser.add_argument(
        "--local-version", help="Local version identifier to add or replace"
    )
    repack_parser.set_defaults(func=pack_f)

    convert_parser = s.add_parser("convert", help="Convert egg or wininst to wheel")
    convert_parser.add_argument("files", nargs="*", help="Files to convert")
    convert_parser.add_argument(
        "--dest-dir",
        "-d",
        default=os.path.curdir,
        help="Directory to store wheels (default %(default)s)",
    )
    convert_parser.add_argument("--verbose", "-v", action="store_true")
    convert_parser.set_defaults(func=convert_f)

    tags_parser = s.add_parser(
        "tags", help="Add or replace the tags on a wheel", description=TAGS_HELP
    )
    tags_parser.add_argument("wheel", nargs="*", help="Existing wheel(s) to retag")
    tags_parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove the original files, keeping only the renamed ones",
    )
    tags_parser.add_argument(
        "--python-tag", metavar="TAG", help="Specify an interpreter tag(s)"
    )
    tags_parser.add_argument("--abi-tag", metavar="TAG", help="Specify an ABI tag(s)")
    tags_parser.add_argument(
        "--platform-tag", metavar="TAG", help="Specify a platform tag(s)"
    )
    tags_parser.add_argument(
        "--build", type=parse_build_tag, metavar="BUILD", help="Specify a build tag"
    )
    tags_parser.set_defaults(func=tags_f)

    info_parser = s.add_parser("info", help="Show information about a wheel file")
    info_parser.add_argument("wheelfile", help="Wheel file to show information for")
    info_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed file listing"
    )
    info_parser.set_defaults(func=info_f)

    delta_parser = s.add_parser(
        "delta",
        help="Create a versioned delta from a base wheel and an overlay",
        description=(
            "Compare a base wheel with an overlay (another wheel or an unpacked "
            "wheel directory) and write a versioned delta describing the added, "
            "replaced and deleted files and the metadata changes. The overlay "
            "must keep the same distribution name and compatibility tags; "
            "version changes require --allow-version-change."
        ),
    )
    delta_parser.add_argument("wheelfile", help="Base wheel file")
    delta_parser.add_argument(
        "overlay", help="Overlay wheel file or unpacked wheel directory"
    )
    delta_parser.add_argument(
        "--dest-dir",
        "-d",
        default=os.path.curdir,
        help="Directory to store the delta in (default %(default)s)",
    )
    delta_parser.add_argument(
        "--allow-version-change",
        action="store_true",
        help="Allow the overlay to use a different distribution version",
    )
    delta_parser.set_defaults(func=delta_f)

    apply_delta_parser = s.add_parser(
        "apply-delta",
        help="Apply a versioned delta to a base wheel",
        description=(
            "Verify the base wheel (whole-file digest, RECORD manifest and file "
            "hashes) and build the resulting wheel with a freshly generated "
            "RECORD. The result is published atomically; a failed application "
            "does not leave a partial wheel behind."
        ),
    )
    apply_delta_parser.add_argument("wheelfile", help="Base wheel file")
    apply_delta_parser.add_argument(
        "delta", help="Delta archive created by 'wheel delta'"
    )
    apply_delta_parser.add_argument(
        "--dest-dir",
        "-d",
        default=os.path.curdir,
        help="Directory to store the resulting wheel in (default %(default)s)",
    )
    apply_delta_parser.set_defaults(func=apply_delta_f)

    version_parser = s.add_parser("version", help="Print version and exit")
    version_parser.set_defaults(func=version_f)

    help_parser = s.add_parser("help", help="Show this help")
    help_parser.set_defaults(func=lambda args: p.print_help())

    return p


def main() -> int:
    p = parser()
    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
    else:
        try:
            args.func(args)
            return 0
        except WheelError as e:
            print(e, file=sys.stderr)

    return 1

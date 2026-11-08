#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: sh tools/reference-vectors.sh /path/to/phc-winner-argon2" >&2
    exit 1
fi

reference=$(CDPATH= cd -- "$1" && pwd)
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
revision=62358ba2123abd17fccf2a108a301d4b52c01a7c
if [ "$(git -C "$reference" rev-parse HEAD)" != "$revision" ]; then
    echo "reference checkout must be at $revision" >&2
    exit 1
fi
if [ -n "$(git -C "$reference" status --porcelain --untracked-files=all -- include src)" ]; then
    echo "reference include/ and src/ must have no local changes" >&2
    exit 1
fi

binary=$(mktemp "${TMPDIR:-/tmp}/argon2-reference-vectors.XXXXXX")
trap 'rm -f -- "$binary"' EXIT
trap 'exit 1' HUP INT TERM
# Match the pinned reference's CI warning policy for unsigned zero bounds.
"${CC:-cc}" -std=c99 -O2 -Wall -Wextra -Wno-type-limits -Werror -DARGON2_NO_THREADS \
    -I"$reference/include" -I"$reference/src" \
    "$root/tools/reference_vectors.c" \
    "$reference/src/argon2.c" "$reference/src/core.c" \
    "$reference/src/blake2/blake2b.c" "$reference/src/thread.c" \
    "$reference/src/encoding.c" "$reference/src/ref.c" \
    -o "$binary"
"$binary"

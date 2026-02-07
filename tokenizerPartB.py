from __future__ import annotations

import os
import sys
from typing import List, Set

from PartA import tokenize_streaming

def count_common_unique_tokens(file1: str, file2: str) -> int:
    """
    Runtime complexity: O(N1 + N2), where N1 and N2 are the number of characters in the two input files
    because the function tokenizes each file in a single linear pass, inserting
    tokens into sets with constant-time average insert and lookup operations. The
    intersection check is linear in the number of unique tokens and does not require
    nested passes over the input.
    """
    try:
        size1 = os.path.getsize(file1)
        size2 = os.path.getsize(file2)
    except OSError:
        size1, size2 = 0, 1

    small, large = (file1, file2) if size1 <= size2 else (file2, file1)

    tokens_small: Set[str] = set()
    for tok in tokenize_streaming(small):
        tokens_small.add(tok)

    common: Set[str] = set()
    for tok in tokenize_streaming(large):
        if tok in tokens_small:
            common.add(tok)

    return len(common)

def _usage_and_exit() -> None:
    """
    Runtime Complexity: O(1) because The function prints a fixed usage message and exits.
    Its execution does not depend on the size of the input file or the
    number of tokens, and it performs a constant amount of work.
    """
    sys.stderr.write("Usage: python PartB.py <text_file_1> <text_file_2>\n")
    sys.exit(2)

def main(argv: List[str]) -> int:
    """
    Runtime Complexity: O(N1 + N2), where N1 and N2 are the number of characters in the two input files.
    because the function validates command-line arguments and then calls
    `count_common_unique_tokens`, which tokenizes each input file in a single
    linear pass. No additional sorting or nested passes over the inputs are
    performed in `main`, so the overall runtime remains linear in the total
    input size.
    """
    if len(argv) != 3:
        _usage_and_exit()

    f1, f2 = argv[1], argv[2]

    try:
        n_common = count_common_unique_tokens(f1, f2)
        sys.stdout.write(f"{n_common}\n")
        return 0

    except FileNotFoundError as e:
        missing = e.filename if getattr(e, "filename", None) else "unknown file"
        sys.stderr.write(f"Error: file not found: {missing}\n")
        return 1
    except PermissionError as e:
        denied = e.filename if getattr(e, "filename", None) else "unknown file"
        sys.stderr.write(f"Error: permission denied: {denied}\n")
        return 1
    except OSError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

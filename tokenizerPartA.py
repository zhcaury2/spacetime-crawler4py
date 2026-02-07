from __future__ import annotations

import sys
from typing import Dict, Iterable, List, Iterator

def _is_ascii_alnum(ch: str) -> bool:
    """
    Runtime Complexity: O(1) because the function checks whether a single character falls within
    fixed ASCII ranges using a constant number of comparisons. Its runtime does
    not depend on input size.
    """
    o = ord(ch)
    return (48 <= o <= 57) or (65 <= o <= 90) or (97 <= o <= 122)

def tokenize_streaming(text_file_path: str, chunk_size: int = 1 << 16) -> Iterator[str]:
    """
    Runtime Complexity: O(N), where N is the number of characters in the input file because
    the function reads the file in fixed-size chunks and processes
    each character exactly once. For each character, it performs constant-time
    checks and buffer operations, and tokens are yielded immediately without
    nested loops or reprocessing.
    """
    token_chars: List[str] = []

    try:
        with open(text_file_path, "r", encoding="utf-8", errors="replace") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                for ch in chunk:
                    if _is_ascii_alnum(ch):
                        token_chars.append(ch.lower())
                    else:
                        if token_chars:
                            yield "".join(token_chars)
                            token_chars.clear()

        if token_chars:
            yield "".join(token_chars)

    except FileNotFoundError:
        raise
    except PermissionError:
        raise
    except OSError as e:
        raise OSError(f"Failed to read file '{text_file_path}': {e}") from e

def tokenize(text_file_path: str) -> List[str]:
    """
    Runtime complexity: O(N), where N is the number of characters in the input file because
    the function delegates to the streaming tokenizer, which
    processes the file in a single pass. Each character is examined exactly
    once with constant-time checks, and tokens are yielded immediately without
    any nested loops or repeated passes over the input.
    """
    return list(tokenize_streaming(text_file_path))

def compute_word_frequencies(tokens: Iterable[str]) -> Dict[str, int]:
    """
    Runtime Complexity : O(T), where T is the number of tokens as the function iterates 
    once over the input token sequence. For each token, it performs a constant-time dictionary 
    lookup and update. There are no nested loops or repeated passes over the tokens.
    """
    freqs: Dict[str, int] = {}
    for tok in tokens:
        freqs[tok] = freqs.get(tok, 0) + 1
    return freqs

def print_frequencies(freqs: Dict[str, int]) -> None:
    """
    Runtime Complexity: O(U log U), where U is the number of unique tokens because the 
    function sorts the dictionary items using Python's built-in `sorted`, which 
    takes O(U log U) time, and then iterates once over the sorted list to print each (token, count) pair.
    """
    for token, count in sorted(freqs.items(), key=lambda kv: (-kv[1], kv[0])):
        # Allowed formats include "<token>\t<freq>"
        sys.stdout.write(f"{token}\t{count}\n")

def _usage_and_exit() -> None:
    """
    Runtime Complexity: O(1) because The function prints a fixed usage message and exits.
    Its execution does not depend on the size of the input file or the
    number of tokens, and it performs a constant amount of work.
    """
    sys.stderr.write("Usage: python PartA.py <text_file>\n")
    sys.exit(2)


def main(argv: List[str]) -> int:
    """
    Runtime Complexity: O(N + U log U), where N is the number of characters in the input file
    and U is the number of unique tokens because the function tokenizes the input file 
    in a single linear pass over N characters and counts token frequencies in linear time with respect
    to the number of tokens. It then sorts the U unique tokens to print them,
    which takes O(U log U) time and dominates the output step.
    """
    if len(argv) != 2:
        _usage_and_exit()

    path = argv[1]

    try:
        tokens = tokenize(path)
        freqs = compute_word_frequencies(tokens)
        print_frequencies(freqs)
        return 0

    except FileNotFoundError:
        sys.stderr.write(f"Error: file not found: {path}\n")
        return 1
    except PermissionError:
        sys.stderr.write(f"Error: permission denied: {path}\n")
        return 1
    except OSError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

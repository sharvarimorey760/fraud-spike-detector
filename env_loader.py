"""
Tiny .env loader — zero dependencies, shared by the agent and dashboard.

Why not python-dotenv? This project pins a minimal requirements.txt and
this loader covers the only thing either entry point needs: read
GEMINI_API_KEY (and any other KEY=VALUE line) from a .env file into
os.environ. Real environment variables always win — an exported key is
never overwritten by the file.

Search order for the .env file (used when no explicit path is given):
the current working directory, then each parent directory up to 4 levels
up. That way the key is found whether the CLI is run from the project
root, from agent/, dashboard/, or detection/.
"""

import os

_ENV_FILENAME = ".env"
_MAX_PARENT_WALK = 4


def _find_env_file(path):
    """Return the path of the nearest .env, searching path and its parents."""
    current = os.path.abspath(path)
    for _ in range(_MAX_PARENT_WALK + 1):
        candidate = os.path.join(current, _ENV_FILENAME)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _parse_line(line):
    """Parse one .env line into (key, value) or None if it holds no entry."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None

    key, _, raw_value = stripped.partition("=")
    key = key.strip()
    value = raw_value.strip()

    # Strip surrounding quotes ("..." or '...').
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return key, value[1:-1]

    # Strip inline comments for unquoted values: KEY=abc # note
    hash_index = value.find(" #")
    if hash_index != -1:
        value = value[:hash_index].rstrip()

    return key, value


def load_dotenv(path=None):
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Existing environment variables are never overwritten. Returns the
    path of the file that was loaded, or None if no .env was found.
    """
    if path is None:
        path = _find_env_file(os.getcwd())
    elif not os.path.isfile(path):
        path = None

    if path is None:
        return None

    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return None

    for line in lines:
        parsed = _parse_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if key and key not in os.environ:
            os.environ[key] = value

    return path
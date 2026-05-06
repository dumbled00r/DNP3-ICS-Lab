#!/bin/sh
# Install hieulw/cicflowmeter on OPNsense WITHOUT scipy.
#
# scipy is only used for `stat.mode()` in 3 files. We replace it with a
# pure-Python mode() and drop scipy from pyproject.toml entirely.
# Avoids the ~30-min meson build of scipy-from-source on FreeBSD.
#
# Idempotent. Re-run after firmware upgrades.

set -eu
WORK=${WORK:-/tmp/cicflowmeter-build}
PYTHON=${PYTHON:-python3}

rm -rf "$WORK"
git clone --depth 1 https://github.com/hieulw/cicflowmeter "$WORK"
cd "$WORK"

# Patch sources: drop scipy import + dep, lower python floor, swap stats.mode.
$PYTHON - <<'PY'
import pathlib, re

SHIM = '''from collections import Counter as _Counter
class _Stat:
    @staticmethod
    def mode(values):
        if not list(values): return [0]
        return [_Counter(values).most_common(1)[0][0]]
stat = _Stat'''

for f in [
    "src/cicflowmeter/features/packet_length.py",
    "src/cicflowmeter/features/packet_time.py",
    "src/cicflowmeter/features/response_time.py",
]:
    p = pathlib.Path(f)
    t = p.read_text()
    if "from scipy import stats as stat" in t:
        p.write_text(t.replace("from scipy import stats as stat", SHIM))
        print(f"patched {f}")

pyp = pathlib.Path("pyproject.toml")
text = pyp.read_text()
text = re.sub(r'^\s*"scipy[^"]*",\s*\n', "", text, flags=re.M)
text = re.sub(r'requires-python\s*=\s*">=3\.12"', 'requires-python = ">=3.10"', text)
pyp.write_text(text)
print("patched pyproject.toml")
PY

pip install --ignore-requires-python .

echo
echo "[+] smoke test:"
$PYTHON -c "import sys; sys.modules['scipy']=None; import cicflowmeter; print('OK ->', cicflowmeter.__file__)"
cicflowmeter --help | head -5

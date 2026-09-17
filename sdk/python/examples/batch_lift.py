"""Lift only explicitly asserted u64(u64,u64) symbols in an existing project.

Usage: python batch_lift.py ENDPOINT TOKEN_FILE PROJECT_ID REVISION OUT_DIR SYMBOL [SYMBOL...]
"""

import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) < 7:
        raise SystemExit(__doc__)
    endpoint, token_file, project_id, revision_text, output_dir, *symbols = sys.argv[1:]
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    with HydirClient(endpoint, token_file) as client:
        for symbol in symbols:
            ir = client.lift(project_id, int(revision_text), symbol, assume_u64x2=True)
            client.export_artifact(ir, output / f"{symbol}.ll")
            print(f"{symbol}: {len(ir)} IR bytes")


if __name__ == "__main__":
    main()

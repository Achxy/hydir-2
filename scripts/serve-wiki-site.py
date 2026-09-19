"""Serve the static wiki locally with Vercel-style clean URLs."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import argparse


SITE = Path(__file__).resolve().parents[1] / "blog"
ROUTES = {"/start", "/architecture", "/blogs", "/articles/patchlang-patchir", "/articles/max2", "/articles/triton-api", "/articles/vm-handler-transfer-function"}


class WikiHandler(SimpleHTTPRequestHandler):
    def _route(self):
        path = urlsplit(self.path).path
        if path in ROUTES:
            self.path = f"{path}.html"

    def do_GET(self):
        self._route()
        super().do_GET()

    def do_HEAD(self):
        self._route()
        super().do_HEAD()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(WikiHandler, directory=str(SITE)))
    print(f"HydIR wiki: http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

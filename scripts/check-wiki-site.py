"""Check static routes and local assets for the hydir.wiki site."""

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "blog"
ROUTES = ("/", "/start", "/architecture", "/blogs", "/articles/patchlang-patchir", "/articles/max2", "/articles/triton-api", "/articles/vm-handler-transfer-function")


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.canonical = []
        self.titles = 0
        self.headings = 0
        self.descriptions = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        elif tag == "img":
            self.images.append(attrs)
            if "src" in attrs:
                self.links.append(attrs["src"])
        elif tag == "link":
            if attrs.get("rel") == "canonical":
                self.canonical.append(attrs.get("href"))
            elif attrs.get("rel") == "stylesheet":
                self.links.append(attrs.get("href", ""))
        elif tag == "script" and "src" in attrs:
            self.links.append(attrs["src"])
        elif tag == "title":
            self.titles += 1
        elif tag == "h1":
            self.headings += 1
        elif tag == "meta" and attrs.get("name") == "description":
            self.descriptions += 1


def file_for_route(route):
    return SITE / ("index.html" if route == "/" else f"{route.lstrip('/')}.html")


errors = []
for route in ROUTES:
    page_path = file_for_route(route)
    if not page_path.is_file():
        errors.append(f"Missing route: {route}")
        continue
    page = Page()
    page.feed(page_path.read_text(encoding="utf-8"))
    if page.canonical != [f"https://hydir.wiki{route}"]:
        errors.append(f"Wrong canonical: {route}: {page.canonical}")
    if (page.titles, page.headings, page.descriptions) != (1, 1, 1):
        errors.append(f"Missing or repeated title/h1/description: {route}")
    if any(not image.get("alt") for image in page.images):
        errors.append(f"Image without alt text: {route}")
    for link in page.links:
        parsed = urlsplit(link)
        if parsed.scheme or parsed.netloc:
            if parsed.netloc == "github.com" and parsed.path.startswith("/Achxy/hydir-2/"):
                parts = parsed.path.split("/", 5)
                if len(parts) == 6 and parts[3:5] in (["blob", "main"], ["tree", "main"]):
                    if not (ROOT / parts[5]).exists():
                        errors.append(f"Broken source link: {route}: {link}")
            continue
        if link.startswith("#"):
            continue
        if not link.startswith("/"):
            errors.append(f"Non-root-relative site link: {route}: {link}")
            continue
        path = parsed.path
        if path in ROUTES:
            target = file_for_route(path)
        else:
            target = SITE / path.lstrip("/")
        if not target.is_file():
            errors.append(f"Broken site link: {route}: {link}")

css = (SITE / "vendor/latex.css/style.css").read_text(encoding="utf-8")
for font in re.findall(r"url\(['\"]?(\./fonts/[^)'\"]+)", css):
    if not (SITE / "vendor/latex.css" / font).is_file():
        errors.append(f"Missing LaTeX.css font: {font}")

ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
sitemap = ET.parse(SITE / "sitemap.xml")
urls = {element.text for element in sitemap.findall("s:url/s:loc", ns)}
expected_urls = {f"https://hydir.wiki{route}" for route in ROUTES}
if urls != expected_urls:
    errors.append(f"Sitemap mismatch: missing={expected_urls - urls}, extra={urls - expected_urls}")
if "Sitemap: https://hydir.wiki/sitemap.xml" not in (SITE / "robots.txt").read_text(encoding="utf-8"):
    errors.append("robots.txt does not reference sitemap")

source_copies = {
    "vm_vadd.S": ROOT / "tests/fixtures/vm_vadd.S",
    "vm_vadd_state.h": ROOT / "tests/fixtures/vm_vadd_state.h",
    "vm_vadd.ll": ROOT / "tests/fixtures/vm_vadd.ll",
    "demo-vm-handler.py": ROOT / "scripts/demo-vm-handler.py",
}
for name, source in source_copies.items():
    published = SITE / "assets/vm-handler" / name
    if not source.is_file() or not published.is_file() or source.read_bytes() != published.read_bytes():
        errors.append(f"Published VM-handler source differs from repository source: {name}")

if errors:
    raise SystemExit("\n".join(errors))
print(f"Checked {len(ROUTES)} routes, local links, images, source paths, fonts, and sitemap")

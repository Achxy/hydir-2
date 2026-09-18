const progressBar = document.querySelector(".reading-progress span");
const article = document.querySelector(".article");
const tocLinks = [...document.querySelectorAll("#toc a")];
const sections = tocLinks
  .map((link) => document.querySelector(link.getAttribute("href")))
  .filter(Boolean);

function updateProgress() {
  const start = article.offsetTop;
  const end = start + article.offsetHeight - window.innerHeight;
  const value = end > start ? (window.scrollY - start) / (end - start) : 0;
  progressBar.style.width = `${Math.max(0, Math.min(1, value)) * 100}%`;
}

const observer = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];

    if (!visible) return;

    tocLinks.forEach((link) => {
      const active = link.getAttribute("href") === `#${visible.target.id}`;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  },
  { rootMargin: "-12% 0px -72% 0px", threshold: [0, 0.25, 1] },
);

sections.forEach((section) => observer.observe(section));
window.addEventListener("scroll", updateProgress, { passive: true });
window.addEventListener("resize", updateProgress);
updateProgress();

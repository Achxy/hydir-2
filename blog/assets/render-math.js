document.addEventListener("DOMContentLoaded", () => {
  const article = document.getElementById("article");
  if (article && typeof renderMathInElement === "function") {
    renderMathInElement(article, {
      delimiters: [
        { left: "\\[", right: "\\]", display: true },
        { left: "\\(", right: "\\)", display: false },
      ],
      throwOnError: false,
    });
  }
});

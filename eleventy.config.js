module.exports = function(eleventyConfig) {
  eleventyConfig.addPassthroughCopy("src/css");
  eleventyConfig.addPassthroughCopy("src/js");
  eleventyConfig.addFilter("paragraphs", function(value) {
    if (!value) {
      return [];
    }
    return String(value)
      .trim()
      .split(/\n\s*\n/)
      .map((paragraph) => paragraph.trim())
      .filter(Boolean);
  });
  // Story prose is written with markdown-style backtick spans. Rendering them
  // as <code> is the whole of the markdown the templates need, so the site does
  // not carry a markdown dependency for it.
  eleventyConfig.addFilter("inlineCode", function(value) {
    const escaped = String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
    return escaped.replace(/`([^`]+)`/g, "<code>$1</code>");
  });
  return {
    dir: {
      input: "src",
      output: "_site"
    }
  }
}

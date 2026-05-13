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
  return {
    dir: {
      input: "src",
      output: "_site"
    }
  }
}

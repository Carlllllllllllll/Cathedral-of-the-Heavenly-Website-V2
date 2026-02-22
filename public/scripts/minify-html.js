const fs = require("fs");
const path = require("path");
const { minify } = require("html-minifier-terser");

const viewsDir = path.join(__dirname, "../views");
const distDir = path.join(__dirname, "../public/dist/views");

const minifyOptions = {
  collapseWhitespace: true,
  removeComments: true,
  removeRedundantAttributes: true,
  removeScriptTypeAttributes: true,
  removeStyleLinkTypeAttributes: true,
  minifyJS: true,
  minifyCSS: true,
  minifyURLs: true,
  useShortDoctype: true,
  removeEmptyAttributes: true,
  removeOptionalTags: true,
  removeAttributeQuotes: true,
  collapseBooleanAttributes: true,
  decodeEntities: true,
  sortAttributes: true,
  sortClassName: true,
  caseSensitive: true,
  keepClosingSlash: false,
  continueOnParseError: true,
  quoteCharacter: '"',
};

async function minifyHTMLFiles() {
  console.log("🔒 Starting HTML minification for maximum security...");

  if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
  }

  const files = fs.readdirSync(viewsDir).filter((f) => f.endsWith(".html"));

  for (const file of files) {
    const inputPath = path.join(viewsDir, file);
    const outputPath = path.join(distDir, file);

    try {
      const html = fs.readFileSync(inputPath, "utf8");
      const minified = await minify(html, minifyOptions);

      fs.writeFileSync(outputPath, minified);

      const originalSize = Buffer.byteLength(html, "utf8");
      const minifiedSize = Buffer.byteLength(minified, "utf8");
      const reduction = ((1 - minifiedSize / originalSize) * 100).toFixed(2);

      console.log(
        `✅ ${file}: ${originalSize} → ${minifiedSize} bytes (${reduction}% reduction)`,
      );
    } catch (error) {
      console.error(`❌ Error minifying ${file}:`, error.message);
    }
  }

  console.log("🎉 HTML minification complete!");
}

minifyHTMLFiles().catch(console.error);

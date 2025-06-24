#!/bin/bash

# Script to sync OpenADP files to homepage directory
# This script copies the necessary files with the correct directory structure

set -e  # Exit on any error

HOMEPAGE_DIR="../openadp_home_page"
SOURCE_DIR="."

echo "🏠 Syncing OpenADP files to homepage directory..."

# Check if homepage directory exists
if [[ ! -d "$HOMEPAGE_DIR" ]]; then
    echo "❌ Homepage directory $HOMEPAGE_DIR does not exist"
    exit 1
fi

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p "$HOMEPAGE_DIR/ghost-notes"
mkdir -p "$HOMEPAGE_DIR/sdk/browser-javascript"

# Copy homepage files (root level)
echo "📄 Copying homepage files..."
cp "$SOURCE_DIR/index.html" "$HOMEPAGE_DIR/"
cp "$SOURCE_DIR/styles.css" "$HOMEPAGE_DIR/"
cp "$SOURCE_DIR/script.js" "$HOMEPAGE_DIR/"
cp "$SOURCE_DIR/developer-quickstart.html" "$HOMEPAGE_DIR/"
cp "$SOURCE_DIR/quickstart-raspberry-pi.html" "$HOMEPAGE_DIR/"
cp "$SOURCE_DIR/LICENSE" "$HOMEPAGE_DIR/"

# Copy Ghost Notes application files
echo "👻 Copying Ghost Notes application files..."
cp "$SOURCE_DIR/ghost-notes/app.js" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/openadp-app.js" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/openadp-ghost.js" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/index.html" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/index-openadp.html" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/styles.css" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/manifest.json" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/sw.js" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/test.html" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/debug.html" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/debug-openadp.html" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/openadp-demo.html" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/README.md" "$HOMEPAGE_DIR/ghost-notes/"
cp "$SOURCE_DIR/ghost-notes/README-OpenADP.md" "$HOMEPAGE_DIR/ghost-notes/"

# Copy Browser SDK files (the key improvement!)
echo "🔧 Copying Browser SDK files..."
cp "$SOURCE_DIR/sdk/browser-javascript/ocrypt.js" "$HOMEPAGE_DIR/sdk/browser-javascript/"
cp "$SOURCE_DIR/sdk/browser-javascript/client.js" "$HOMEPAGE_DIR/sdk/browser-javascript/"
cp "$SOURCE_DIR/sdk/browser-javascript/keygen.js" "$HOMEPAGE_DIR/sdk/browser-javascript/"
cp "$SOURCE_DIR/sdk/browser-javascript/crypto.js" "$HOMEPAGE_DIR/sdk/browser-javascript/"
cp "$SOURCE_DIR/sdk/browser-javascript/noise-nk.js" "$HOMEPAGE_DIR/sdk/browser-javascript/"
cp "$SOURCE_DIR/sdk/browser-javascript/package.json" "$HOMEPAGE_DIR/sdk/browser-javascript/"
cp "$SOURCE_DIR/sdk/browser-javascript/README.md" "$HOMEPAGE_DIR/sdk/browser-javascript/"

# Remove old ghost-notes SDK files (they should import from sdk/browser-javascript now)
echo "🧹 Cleaning up old duplicate SDK files from ghost-notes..."
rm -f "$HOMEPAGE_DIR/ghost-notes/ocrypt.js"
rm -f "$HOMEPAGE_DIR/ghost-notes/client.js"
rm -f "$HOMEPAGE_DIR/ghost-notes/keygen.js"
rm -f "$HOMEPAGE_DIR/ghost-notes/crypto.js"
rm -f "$HOMEPAGE_DIR/ghost-notes/noise-nk.js"

# Update the files list
echo "📝 Updating files list..."
cat > "$HOMEPAGE_DIR/files" << EOF
./LICENSE
./index.html
./developer-quickstart.html
./quickstart-raspberry-pi.html
./styles.css
./script.js
./ghost-notes/test.html
./ghost-notes/openadp-app.js
./ghost-notes/openadp-ghost.js
./ghost-notes/sw.js
./ghost-notes/app.js
./ghost-notes/openadp-demo.html
./ghost-notes/index.html
./ghost-notes/manifest.json
./ghost-notes/index-openadp.html
./ghost-notes/README-OpenADP.md
./ghost-notes/debug.html
./ghost-notes/debug-openadp.html
./ghost-notes/styles.css
./ghost-notes/README.md
./sdk/browser-javascript/ocrypt.js
./sdk/browser-javascript/client.js
./sdk/browser-javascript/keygen.js
./sdk/browser-javascript/crypto.js
./sdk/browser-javascript/noise-nk.js
./sdk/browser-javascript/package.json
./sdk/browser-javascript/README.md
EOF

echo ""
echo "✅ Homepage sync complete!"
echo ""
echo "📁 Directory structure:"
echo "   $HOMEPAGE_DIR/"
echo "   ├── index.html, styles.css, etc.  (homepage files)"
echo "   ├── ghost-notes/                  (Ghost Notes app files)"
echo "   └── sdk/browser-javascript/       (Browser SDK files)"
echo ""
echo "🎯 Key improvements:"
echo "   • Ghost Notes now imports from ../sdk/browser-javascript/"
echo "   • No duplicate SDK files in ghost-notes/"
echo "   • Proper separation of concerns"
echo "   • Developer quickstart guide points to working browser SDK"
echo ""
echo "🌐 To view the homepage:"
echo "   Run: ./scripts/serve_homepage.py"
echo "   (Don't open index.html directly - browsers block ES6 modules from file://)" 
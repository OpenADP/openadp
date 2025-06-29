#!/usr/bin/env python3
"""
OpenADP 0.1.2 Release Script

This script handles the complete release process for OpenADP version 0.1.2
across all supported language ecosystems:
- Go
- Python (PyPI)
- JavaScript Node.js (npm)
- JavaScript Browser (npm)
- Rust (crates.io)
- C++

Usage:
    python release_0_1_2.py --update-versions    # Update all version numbers
    python release_0_1_2.py --build-all          # Build all packages
    python release_0_1_2.py --publish-all        # Publish to package registries
    python release_0_1_2.py --full-release       # Do everything
"""

import os
import sys
import subprocess
import json
import re
from pathlib import Path
import argparse

# Target version for this release
TARGET_VERSION = "0.1.2"

def log(message):
    print(f"🚀 [RELEASE] {message}")

def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result"""
    log(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    
    if check and result.returncode != 0:
        log(f"❌ Command failed: {' '.join(cmd)}")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        raise subprocess.CalledProcessError(result.returncode, cmd)
    
    return result

def update_file_version(file_path, version_pattern, new_version_string):
    """Update version in a file using regex pattern"""
    log(f"Updating {file_path}")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    original_content = content
    content = re.sub(version_pattern, new_version_string, content)
    
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        log(f"  ✅ Updated {file_path}")
        return True
    else:
        log(f"  ⚠️  No changes needed in {file_path}")
        return False

def update_versions():
    """Update all version numbers to TARGET_VERSION"""
    log(f"🔄 Updating all versions to {TARGET_VERSION}")
    
    updates = []
    
    # 1. Makefile (Go main version)
    updates.append(update_file_version(
        "Makefile",
        r"VERSION=[\d\.]+",
        f"VERSION={TARGET_VERSION}"
    ))
    
    # 2. Python SDK
    updates.append(update_file_version(
        "sdk/python/setup.py",
        r'version="[\d\.]+"',
        f'version="{TARGET_VERSION}"'
    ))
    
    updates.append(update_file_version(
        "sdk/python/openadp/__init__.py",
        r'__version__ = "[\d\.]+"',
        f'__version__ = "{TARGET_VERSION}"'
    ))
    
    # 3. JavaScript Node.js SDK
    # Read, update, and write JSON properly
    js_package_path = "sdk/javascript/package.json"
    with open(js_package_path, 'r') as f:
        js_package = json.load(f)
    
    if js_package.get("version") != TARGET_VERSION:
        js_package["version"] = TARGET_VERSION
        with open(js_package_path, 'w') as f:
            json.dump(js_package, f, indent=2)
        log(f"  ✅ Updated {js_package_path}")
        updates.append(True)
    else:
        log(f"  ⚠️  No changes needed in {js_package_path}")
        updates.append(False)
    
    # 4. JavaScript Browser SDK
    browser_package_path = "sdk/browser-javascript/package.json"
    with open(browser_package_path, 'r') as f:
        browser_package = json.load(f)
    
    if browser_package.get("version") != TARGET_VERSION:
        browser_package["version"] = TARGET_VERSION
        with open(browser_package_path, 'w') as f:
            json.dump(browser_package, f, indent=2)
        log(f"  ✅ Updated {browser_package_path}")
        updates.append(True)
    else:
        log(f"  ⚠️  No changes needed in {browser_package_path}")
        updates.append(False)
    
    # 5. Rust SDK (only update package version, not dependency versions)
    updates.append(update_file_version(
        "sdk/rust/Cargo.toml",
        r'^version = "[\d\.]+"',
        f'version = "{TARGET_VERSION}"'
    ))
    
    # 6. Go binary version constants
    go_files = [
        "cmd/openadp-server/main.go",
        "cmd/openadp-encrypt/main.go", 
        "cmd/openadp-decrypt/main.go",
        "cmd/openadp-serverinfo/main.go"
    ]
    
    for go_file in go_files:
        if os.path.exists(go_file):
            updates.append(update_file_version(
                go_file,
                r'version = "[\d\.]+"',
                f'version = "{TARGET_VERSION}"'
            ))
    
    # 7. Tool versions in Python/JavaScript
    tool_files = [
        ("sdk/python/openadp-encrypt.py", r'VERSION = "[\d\.]+"', f'VERSION = "{TARGET_VERSION}"'),
        ("sdk/python/openadp-decrypt.py", r'VERSION = "[\d\.]+"', f'VERSION = "{TARGET_VERSION}"'),
        ("sdk/python/openadp/ocrypt.py", r'__version__ = "[\d\.]+"', f'__version__ = "{TARGET_VERSION}"'),
        ("sdk/javascript/openadp-encrypt.js", r'const VERSION = "[\d\.]+"', f'const VERSION = "{TARGET_VERSION}"'),
        ("sdk/javascript/openadp-decrypt.js", r'const VERSION = "[\d\.]+"', f'const VERSION = "{TARGET_VERSION}"'),
    ]
    
    for file_path, pattern, replacement in tool_files:
        if os.path.exists(file_path):
            updates.append(update_file_version(file_path, pattern, replacement))
    
    # 8. Rust binary versions
    rust_binaries = [
        "sdk/rust/src/bin/ocrypt-register.rs",
        "sdk/rust/src/bin/ocrypt-recover.rs", 
        "sdk/rust/src/bin/openadp-encrypt.rs",
        "sdk/rust/src/bin/openadp-decrypt.rs"
    ]
    
    for rust_file in rust_binaries:
        if os.path.exists(rust_file):
            # Handle both clap version attributes and const VERSION
            updates.append(update_file_version(
                rust_file,
                r'#\[command\(version = "[\d\.]+"\)\]',
                f'#[command(version = "{TARGET_VERSION}")]'
            ))
            updates.append(update_file_version(
                rust_file,
                r'const VERSION: &str = "[\d\.]+"',
                f'const VERSION: &str = "{TARGET_VERSION}"'
            ))
    
    total_updates = sum(updates)
    log(f"✅ Version update complete: {total_updates} files updated")
    
    return total_updates > 0

def build_go():
    """Build Go binaries"""
    log("🔨 Building Go binaries...")
    
    # Clean and build
    run_command("make clean")
    run_command("make build")
    
    log("✅ Go build complete")

def build_python():
    """Build Python package"""
    log("🔨 Building Python package...")
    
    os.chdir("sdk/python")
    try:
        # Clean previous builds
        run_command("rm -rf build dist *.egg-info", check=False)
        
        # Install build dependencies if needed
        run_command(["pip", "install", "build", "wheel", "setuptools"], check=False)
        
        # Build using modern Python build tool
        result = run_command(["python", "-m", "build"], check=False)
        
        if result.returncode != 0:
            # Fallback to setuptools method
            log("⚠️  Modern build failed, trying setuptools...")
            run_command(["python", "setup.py", "sdist", "bdist_wheel"])
        
        log("✅ Python build complete")
    finally:
        os.chdir("../..")

def build_javascript():
    """Build JavaScript packages"""
    log("🔨 Building JavaScript packages...")
    
    # Node.js package
    os.chdir("sdk/javascript")
    try:
        run_command(["npm", "install"])
        run_command(["npm", "run", "build"], check=False)  # May not have build script
        log("✅ JavaScript Node.js package ready")
    finally:
        os.chdir("../..")
    
    # Browser package - may need different build process
    os.chdir("sdk/browser-javascript")
    try:
        # No build needed for simple browser package
        log("✅ JavaScript Browser package ready")
    finally:
        os.chdir("../..")

def build_rust():
    """Build Rust package"""
    log("🔨 Building Rust package...")
    
    os.chdir("sdk/rust")
    try:
        # Clean and build
        run_command(["cargo", "clean"])
        run_command(["cargo", "build", "--release"])
        run_command(["cargo", "test"])
        
        log("✅ Rust build complete")
    finally:
        os.chdir("../..")

def create_git_tag():
    """Create and push git tag"""
    log(f"🏷️  Creating git tag v{TARGET_VERSION}")
    
    # Add all changes
    run_command(["git", "add", "."])
    
    # Commit version updates
    run_command(["git", "commit", "-m", f"Release version {TARGET_VERSION}"])
    
    # Create tag
    run_command(["git", "tag", "-a", f"v{TARGET_VERSION}", "-m", f"Release version {TARGET_VERSION}"])
    
    # Push commits and tags
    run_command(["git", "push", "origin", "main"])
    run_command(["git", "push", "origin", f"v{TARGET_VERSION}"])
    
    log("✅ Git tag created and pushed")

def publish_python():
    """Publish Python package to PyPI"""
    log("📦 Publishing Python package to PyPI...")
    
    os.chdir("sdk/python")
    try:
        # Use twine to publish (assumes it's installed and configured)
        result = run_command(["twine", "upload", "dist/*"], check=False)
        
        if result.returncode == 0:
            log("✅ Python package published to PyPI")
        else:
            log("⚠️  Python publish failed - may need to configure twine credentials")
            log("   Run: twine configure")
            log("   Or set TWINE_USERNAME and TWINE_PASSWORD environment variables")
    finally:
        os.chdir("../..")

def publish_javascript():
    """Publish JavaScript packages to npm"""
    log("📦 Publishing JavaScript packages to npm...")
    
    # Node.js package
    os.chdir("sdk/javascript")
    try:
        result = run_command(["npm", "publish", "--access", "public"], check=False)
        
        if result.returncode == 0:
            log("✅ JavaScript Node.js package published to npm")
        else:
            log("⚠️  JavaScript Node.js publish failed - may need to login to npm")
            log("   Run: npm login")
    finally:
        os.chdir("../..")
    
    # Browser package
    os.chdir("sdk/browser-javascript")
    try:
        result = run_command(["npm", "publish", "--access", "public"], check=False)
        
        if result.returncode == 0:
            log("✅ JavaScript Browser package published to npm")
        else:
            log("⚠️  JavaScript Browser publish failed - may need to login to npm")
    finally:
        os.chdir("../..")

def publish_rust():
    """Publish Rust package to crates.io"""
    log("📦 Publishing Rust package to crates.io...")
    
    os.chdir("sdk/rust")
    try:
        result = run_command(["cargo", "publish"], check=False)
        
        if result.returncode == 0:
            log("✅ Rust package published to crates.io")
        else:
            log("⚠️  Rust publish failed - may need to login to crates.io")
            log("   Run: cargo login")
    finally:
        os.chdir("../..")

def create_github_release():
    """Create GitHub release with binaries"""
    log("🚀 Creating GitHub release...")
    
    # This would typically use GitHub CLI or API
    log("⚠️  GitHub release creation requires manual step:")
    log(f"   1. Go to https://github.com/openadp/openadp/releases/new")
    log(f"   2. Use tag: v{TARGET_VERSION}")
    log(f"   3. Upload binaries from build/ directory")
    log(f"   4. Include release notes")

def main():
    parser = argparse.ArgumentParser(description="OpenADP 0.1.2 Release Script")
    parser.add_argument("--update-versions", action="store_true", help="Update all version numbers")
    parser.add_argument("--build-all", action="store_true", help="Build all packages")
    parser.add_argument("--publish-all", action="store_true", help="Publish to all package registries")
    parser.add_argument("--full-release", action="store_true", help="Complete release process")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without doing it")
    
    args = parser.parse_args()
    
    if not any([args.update_versions, args.build_all, args.publish_all, args.full_release]):
        parser.print_help()
        return
    
    if args.dry_run:
        log("🧪 DRY RUN MODE - showing what would be done")
        return
    
    try:
        if args.update_versions or args.full_release:
            if update_versions():
                log("✅ All versions updated successfully")
            else:
                log("ℹ️  No version updates were needed")
        
        if args.build_all or args.full_release:
            log("🔨 Building all packages...")
            build_go()
            build_python()
            build_javascript()
            build_rust()
            log("✅ All builds complete")
        
        if args.full_release:
            create_git_tag()
        
        if args.publish_all or args.full_release:
            log("📦 Publishing to package registries...")
            publish_python()
            publish_javascript()
            publish_rust()
            create_github_release()
            log("✅ Publishing complete")
        
        log(f"🎉 OpenADP {TARGET_VERSION} release process completed!")
        
    except subprocess.CalledProcessError as e:
        log(f"❌ Release failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        log("⚠️  Release interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main() 
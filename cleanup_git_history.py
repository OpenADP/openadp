#!/usr/bin/env python3
"""
Clean up git history by removing large binary files and build artifacts.

This script removes:
- Compiled binaries (openadp-server, openadp-cli, etc.)
- Virtual environment directories (.venv/, venv/)
- Large binary shared libraries (.so, .dylib files)
- Build artifacts and temporary files

WARNING: This rewrites git history and should only be run on a local repository
before pushing to remote. All contributors will need to re-clone after this operation.
"""

import subprocess
import sys
import os

def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    return result

def check_git_status():
    """Check if git working directory is clean."""
    result = run_command("git status --porcelain", check=False)
    if result.stdout.strip():
        print("Error: Git working directory is not clean. Please commit or stash changes first.")
        print("Uncommitted changes:")
        print(result.stdout)
        sys.exit(1)

def backup_current_branch():
    """Create a backup of the current branch."""
    result = run_command("git branch --show-current")
    current_branch = result.stdout.strip()
    backup_branch = f"{current_branch}-backup-{int(subprocess.check_output(['date', '+%s']).decode().strip())}"
    run_command(f"git branch {backup_branch}")
    print(f"Created backup branch: {backup_branch}")
    return backup_branch

def get_repo_size():
    """Get current repository size."""
    result = run_command("du -sh .git/")
    return result.stdout.strip().split()[0]

def clean_git_history():
    """Clean up git history using git-filter-repo."""
    
    # Patterns to remove from history
    patterns_to_remove = [
        # Compiled binaries
        "--path-glob", "*/openadp-server",
        "--path-glob", "*/openadp-cli", 
        "--path-glob", "*/openadp-encrypt",
        "--path-glob", "*/openadp-decrypt",
        
        # Virtual environments
        "--path-glob", ".venv/**",
        "--path-glob", "venv/**",
        
        # Large binary files
        "--path-glob", "*.so",
        "--path-glob", "*.dylib",
        "--path-glob", "*.dll",
        
        # Build artifacts
        "--path-glob", "build/**",
        "--path-glob", "dist/**",
        "--path-glob", "*.egg-info/**",
        
        # Temporary and test files
        "--path-glob", "*.enc",
        "--path-glob", "*.tmp",
        "--path-glob", "*.temp",
        "--path-glob", "test-file*",
    ]
    
    # Build the git-filter-repo command
    cmd_parts = ["git", "filter-repo", "--force"] + patterns_to_remove + ["--invert-paths"]
    cmd = " ".join(cmd_parts)
    
    print("Cleaning git history...")
    print("This may take a few minutes...")
    
    result = run_command(cmd, check=False)
    if result.returncode != 0:
        print(f"git-filter-repo output: {result.stdout}")
        print(f"git-filter-repo errors: {result.stderr}")
        if "not a fresh clone" in result.stderr:
            print("\nNote: git-filter-repo requires a fresh clone for safety.")
            print("If you're sure you want to proceed, you can add --force flag.")
        return False
    
    return True

def main():
    print("Git History Cleanup Script")
    print("=" * 50)
    
    # Check if we're in a git repository
    if not os.path.exists(".git"):
        print("Error: Not in a git repository")
        sys.exit(1)
    
    # Get initial size
    initial_size = get_repo_size()
    print(f"Initial repository size: {initial_size}")
    
    # Check git status
    check_git_status()
    
    # Create backup
    backup_branch = backup_current_branch()
    
    # Show what we're going to remove
    print("\nFiles that will be removed from history:")
    large_files_cmd = """git rev-list --objects --all | 
                        git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | 
                        awk '/^blob/ {print substr($0,6)}' | 
                        sort -k2nr | 
                        head -10"""
    
    result = run_command(large_files_cmd, check=False)
    if result.stdout:
        print(result.stdout)
    
    # Confirm with user
    response = input("\nProceed with cleaning git history? This cannot be undone easily. (y/N): ")
    if response.lower() != 'y':
        print("Aborted.")
        sys.exit(0)
    
    # Clean the history
    if clean_git_history():
        # Get final size
        final_size = get_repo_size()
        print(f"\nCleanup completed!")
        print(f"Repository size: {initial_size} -> {final_size}")
        
        # Show statistics
        run_command("git count-objects -vH")
        
        print(f"\nBackup branch created: {backup_branch}")
        print("If everything looks good, you can delete the backup with:")
        print(f"  git branch -D {backup_branch}")
        
        print("\nNext steps:")
        print("1. Test that everything still works")
        print("2. If pushing to remote: git push --force-with-lease")
        print("3. All collaborators will need to re-clone the repository")
        
    else:
        print("Cleanup failed. Repository unchanged.")
        sys.exit(1)

if __name__ == "__main__":
    main() 
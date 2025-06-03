#!/bin/bash
# Git Setup and Upload Guide for RMM Repository

echo "=== Git Repository Setup and Upload Guide ==="
echo ""

# Step 1: Clone your repository
echo "1. Clone your GitHub repository locally:"
echo "   git clone https://github.com/cs-sec/rustaceans-rmm-complete.git"
echo "   cd rustaceans-rmm-complete"
echo ""

# Step 2: Download and extract the updated files
echo "2. Download the tar.gz file from Replit and extract:"
echo "   # Download rustaceans-rmm-complete.tar.gz from Replit"
echo "   tar -xzf rustaceans-rmm-complete.tar.gz"
echo ""

# Step 3: Copy only changed files
echo "3. Copy the specific changed files to your repo:"
echo ""
echo "   # Main server file (fixed database issues)"
echo "   cp extracted/src/simple_server.rs src/"
echo ""
echo "   # Fixed JavaScript file (corrected API endpoints)"
echo "   cp extracted/static/app.js static/"
echo ""
echo "   # Updated dependencies"
echo "   cp extracted/Cargo.toml ."
echo ""
echo "   # New deployment scripts"
echo "   cp -r extracted/deployment/* deployment/"
echo ""

# Step 4: Check what changed
echo "4. Review the changes:"
echo "   git status"
echo "   git diff"
echo ""

# Step 5: Commit specific changes
echo "5. Commit only the fixes:"
echo "   git add src/simple_server.rs"
echo "   git add static/app.js" 
echo "   git add Cargo.toml"
echo "   git add deployment/"
echo ""
echo "   git commit -m \"Fix: Resolve database permission errors and API endpoint issues"
echo ""
echo "   - Remove PostgreSQL dependencies causing permission errors"
echo "   - Fix frontend JavaScript to match available server endpoints"
echo "   - Simplify build process for easier AWS deployment"
echo "   - Maintain full authentication and dashboard functionality\""
echo ""

# Step 6: Push changes
echo "6. Push to GitHub:"
echo "   git push origin main"
echo ""

echo "=== Key Files That Changed ==="
echo ""
echo "src/simple_server.rs:"
echo "  - Removed database dependencies"
echo "  - Simplified server to work without PostgreSQL permissions"
echo "  - Maintained all API endpoints for dashboard"
echo ""
echo "static/app.js:"
echo "  - Fixed API calls to match server endpoints"
echo "  - Removed calls to non-existent endpoints"
echo "  - Maintained full dashboard functionality"
echo ""
echo "Cargo.toml:"
echo "  - Removed sqlx and database dependencies"
echo "  - Added uuid dependency for session management"
echo "  - Simplified for standalone operation"
echo ""
echo "deployment/:"
echo "  - Updated scripts for GitHub repository"
echo "  - Fixed download URLs to use correct repo"
echo "  - Added comprehensive setup guides"
echo ""

echo "After uploading, your deployment command will work:"
echo "curl -sSL https://raw.githubusercontent.com/cs-sec/rustaceans-rmm-complete/main/deployment/github-upgrade.sh | bash"
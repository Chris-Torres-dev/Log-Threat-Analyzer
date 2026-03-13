#!/bin/bash
# ============================================================
# Log Threat Analyzer — Branch Setup Script
# Run this ONCE after pushing the new structure to GitHub
# Usage: bash setup_branches.sh
# ============================================================

echo "🌿 Setting up branch structure for Log-Threat-Analyzer..."

# Make sure we're on main and up to date
git checkout main
git pull origin main

# Create dev branch (all features merge here first)
git checkout -b dev
git push -u origin dev
echo "✅ Created: dev"

# Feature branches
branches=(
  "feature/engine-parser"
  "feature/threat-detection"
  "feature/dashboard-ui"
  "feature/terminal-cli"
  "feature/log-import"
  "feature/report-export"
)

for branch in "${branches[@]}"; do
  git checkout dev
  git checkout -b "$branch"
  git push -u origin "$branch"
  echo "✅ Created: $branch"
done

# Return to dev for active work
git checkout dev

echo ""
echo "🎉 All branches created! Your structure:"
echo ""
echo "  main                  ← stable releases only"
echo "  dev                   ← merge all features here"
echo "  feature/engine-parser         ← C++ parsing work"
echo "  feature/threat-detection      ← detection logic"
echo "  feature/dashboard-ui          ← React frontend"
echo "  feature/terminal-cli          ← CLI improvements"
echo "  feature/log-import            ← log file importing"
echo "  feature/report-export         ← JSON/PDF reports"
echo ""
echo "👉 You are now on: dev"
echo "   Start new work with: git checkout -b feature/your-feature dev"

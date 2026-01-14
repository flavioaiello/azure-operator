#!/bin/bash
# sync.sh - Sync ALZ policy definitions from Enterprise-Scale repository
#
# Usage:
#   ./sync.sh              # Sync from latest release
#   ./sync.sh 2025-09-17   # Sync from specific release tag
#
# This script fetches policy definitions and initiatives from the official
# Azure Landing Zones (Enterprise-Scale) repository and copies them to
# the local lib/policies/ directory.
#
# It also generates combined JSON files for Bicep's loadJsonContent():
#   - definitions.json (array of all policy definitions)
#   - initiatives.json (array of all policy initiatives)

set -euo pipefail

# Configuration
ALZ_REPO="https://github.com/Azure/Enterprise-Scale"
ALZ_REPO_NAME="Azure/Enterprise-Scale"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFINITIONS_DIR="${SCRIPT_DIR}/definitions"
INITIATIVES_DIR="${SCRIPT_DIR}/initiatives"
VERSION_FILE="${SCRIPT_DIR}/VERSION"
COMBINED_DEFINITIONS="${SCRIPT_DIR}/definitions.json"
COMBINED_INITIATIVES="${SCRIPT_DIR}/initiatives.json"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
trap "rm -rf ${TEMP_DIR}" EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Generate combined JSON array from directory of JSON files
generate_combined_json() {
    local source_dir="$1"
    local output_file="$2"
    local type_name="$3"
    
    local count=0
    echo "[" > "$output_file"
    
    local first=true
    for file in "$source_dir"/*.json; do
        [[ -f "$file" ]] || continue
        
        # Skip cloud-specific files (AzureChinaCloud, AzureUSGovernment)
        # unless they're the only version available
        local basename=$(basename "$file" .json)
        if [[ "$basename" == *".AzureChinaCloud" ]] || [[ "$basename" == *".AzureUSGovernment" ]]; then
            continue
        fi
        
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "$output_file"
        fi
        
        # Add the JSON content (remove trailing newline, indent)
        cat "$file" >> "$output_file"
        ((count++))
    done
    
    echo "" >> "$output_file"
    echo "]" >> "$output_file"
    
    log_info "Generated ${output_file} with ${count} ${type_name}"
}

# Get latest release tag if not specified
get_latest_release() {
    curl -s "https://api.github.com/repos/${ALZ_REPO_NAME}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Main sync function
sync_policies() {
    local version="${1:-}"
    
    # Determine version to sync
    if [[ -z "$version" ]]; then
        log_info "Fetching latest ALZ release..."
        version=$(get_latest_release)
        if [[ -z "$version" ]]; then
            log_error "Failed to determine latest release. Specify version manually."
            exit 1
        fi
    fi
    
    log_info "Syncing ALZ policies version: ${version}"
    
    # Check current version
    if [[ -f "$VERSION_FILE" ]]; then
        current_version=$(cat "$VERSION_FILE")
        if [[ "$current_version" == "$version" ]]; then
            log_warn "Already at version ${version}. Use -f to force re-sync."
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
        fi
    fi
    
    # Clone specific tag (shallow clone for speed)
    log_info "Cloning Enterprise-Scale repository (tag: ${version})..."
    git clone --depth 1 --branch "$version" "$ALZ_REPO" "${TEMP_DIR}/alz" 2>/dev/null || {
        log_error "Failed to clone. Is '${version}' a valid tag?"
        log_info "Available releases: https://github.com/${ALZ_REPO_NAME}/releases"
        exit 1
    }
    
    # Ensure target directories exist
    mkdir -p "$DEFINITIONS_DIR"
    mkdir -p "$INITIATIVES_DIR"
    
    # Source paths in Enterprise-Scale repo
    local src_definitions="${TEMP_DIR}/alz/src/resources/Microsoft.Authorization/policyDefinitions"
    local src_initiatives="${TEMP_DIR}/alz/src/resources/Microsoft.Authorization/policySetDefinitions"
    
    # Verify source paths exist
    if [[ ! -d "$src_definitions" ]]; then
        log_error "Policy definitions not found at expected path"
        exit 1
    fi
    
    # Count before
    local before_defs=$(find "$DEFINITIONS_DIR" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    local before_inits=$(find "$INITIATIVES_DIR" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
    
    # Copy definitions
    log_info "Copying policy definitions..."
    cp "${src_definitions}"/*.json "$DEFINITIONS_DIR/" 2>/dev/null || true
    
    # Copy initiatives (policy set definitions)
    log_info "Copying policy initiatives..."
    if [[ -d "$src_initiatives" ]]; then
        cp "${src_initiatives}"/*.json "$INITIATIVES_DIR/" 2>/dev/null || true
    fi
    
    # Generate combined JSON files for Bicep loadJsonContent()
    log_info "Generating combined JSON files for Bicep..."
    generate_combined_json "$DEFINITIONS_DIR" "$COMBINED_DEFINITIONS" "definitions"
    generate_combined_json "$INITIATIVES_DIR" "$COMBINED_INITIATIVES" "initiatives"
    
    # Count after
    local after_defs=$(find "$DEFINITIONS_DIR" -name "*.json" | wc -l | tr -d ' ')
    local after_inits=$(find "$INITIATIVES_DIR" -name "*.json" | wc -l | tr -d ' ')
    
    # Write version file
    echo "$version" > "$VERSION_FILE"
    
    # Summary
    echo ""
    log_info "Sync complete!"
    echo "  Version:     ${version}"
    echo "  Definitions: ${after_defs} (was: ${before_defs})"
    echo "  Initiatives: ${after_inits} (was: ${before_inits})"
    echo "  Version file: ${VERSION_FILE}"
    echo ""
    log_info "Next steps:"
    echo "  1. Review changes: git diff lib/policies/"
    echo "  2. Commit: git add lib/policies/ && git commit -m 'chore: sync ALZ policies to ${version}'"
}

# Show help
show_help() {
    echo "Usage: $0 [VERSION]"
    echo ""
    echo "Sync ALZ policy definitions from Azure/Enterprise-Scale repository."
    echo ""
    echo "Arguments:"
    echo "  VERSION    Optional. ALZ release tag (e.g., 2025-09-17)"
    echo "             If not specified, syncs from latest release."
    echo ""
    echo "Examples:"
    echo "  $0                  # Sync latest release"
    echo "  $0 2025-09-17       # Sync specific version"
    echo ""
    echo "Current version: $(cat "$VERSION_FILE" 2>/dev/null || echo 'not synced')"
}

# Parse arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    *)
        sync_policies "${1:-}"
        ;;
esac

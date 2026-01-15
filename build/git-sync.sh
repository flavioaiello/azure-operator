#!/bin/sh
# git-sync.sh - Synchronizes a Git repository to a local directory
# Designed to run as a sidecar container

set -e

# Configuration from environment
GIT_REPO="${GIT_REPO:?GIT_REPO environment variable is required}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GIT_SYNC_DEST="${GIT_SYNC_DEST:-/specs}"
GIT_SYNC_INTERVAL="${GIT_SYNC_INTERVAL:-60}"
GIT_SYNC_SUBPATH="${GIT_SYNC_SUBPATH:-specs}"
GIT_SSH_KEY_PATH="${GIT_SSH_KEY_PATH:-/ssh/id_rsa}"

# Setup SSH if key exists
if [ -f "$GIT_SSH_KEY_PATH" ]; then
    mkdir -p ~/.ssh
    cp "$GIT_SSH_KEY_PATH" ~/.ssh/id_rsa
    chmod 600 ~/.ssh/id_rsa
    ssh-keyscan -H github.com >> ~/.ssh/known_hosts 2>/dev/null
    ssh-keyscan -H gitlab.com >> ~/.ssh/known_hosts 2>/dev/null
    ssh-keyscan -H dev.azure.com >> ~/.ssh/known_hosts 2>/dev/null
fi

CLONE_DIR="/tmp/repo"

log() {
    local message="$1"
    echo "[$(date -Iseconds)] $message"
    return 0
}

sync_repo() {
    if [ ! -d "$CLONE_DIR/.git" ]; then
        log "Initial clone of $GIT_REPO"
        git clone --depth 1 --single-branch --branch "$GIT_BRANCH" "$GIT_REPO" "$CLONE_DIR"
    else
        log "Fetching updates from $GIT_BRANCH"
        cd "$CLONE_DIR"
        git fetch --depth 1 origin "$GIT_BRANCH"
        git reset --hard "origin/$GIT_BRANCH"
    fi

    # Copy specs to destination
    if [ -n "$GIT_SYNC_SUBPATH" ] && [ -d "$CLONE_DIR/$GIT_SYNC_SUBPATH" ]; then
        log "Syncing $GIT_SYNC_SUBPATH to $GIT_SYNC_DEST"
        cp -r "$CLONE_DIR/$GIT_SYNC_SUBPATH"/* "$GIT_SYNC_DEST/"
    else
        log "Syncing repository root to $GIT_SYNC_DEST"
        cp -r "$CLONE_DIR"/* "$GIT_SYNC_DEST/"
    fi

    log "Sync complete"
    return 0
}

# Initial sync
sync_repo

# Continuous sync loop
while true; do
    sleep "$GIT_SYNC_INTERVAL"
    sync_repo || log "Sync failed, will retry"
done

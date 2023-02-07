#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -eEuo pipefail

MNT_PATH="gcp"
PLUGIN_NAME="vault-plugin-auth-gcp"

#
# Helper script for local development. Automatically builds and registers the
# plugin. Requires `vault` is installed and available on $PATH.
#

# Get the right dir
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "==> Starting dev"

echo "--> Scratch dir"
echo "    Creating"
SCRATCH="${DIR}/tmp"
mkdir -p "${SCRATCH}/plugins"

function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "${VAULT_PID}"
  rm -rf "${SCRATCH}"
}
trap cleanup EXIT

echo "--> Building"
go build -o "${SCRATCH}/plugins/${PLUGIN_NAME}"

echo "--> Starting server"

export VAULT_TOKEN="root"
export VAULT_ADDR="http://127.0.0.1:8200"

vault server \
  -dev \
  -dev-plugin-init \
  -dev-plugin-dir "${SCRATCH}/plugins" \
  -dev-root-token-id "root" \
  -log-level "debug" \
  &
sleep 2
VAULT_PID=$!

echo "    Mounting plugin"
vault auth enable -path=${MNT_PATH} -plugin-name=${PLUGIN_NAME} plugin

echo "==> Ready!"
wait ${VAULT_PID}

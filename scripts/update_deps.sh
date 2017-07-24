#!/bin/sh

set -e

TOOL=vault-plugin-auth-gcp

## Make a temp dir
tempdir=$(mktemp -d update-${TOOL}-deps.XXXXXX)

## Set paths
export GOPATH="$(pwd)/${tempdir}"
export PATH="${GOPATH}/bin:${PATH}"
cd $tempdir

## Get tool
mkdir -p src/github.com/hashicorp
cd src/github.com/hashicorp
echo "Fetching ${TOOL}..."
git clone git@github.com:hashicorp/${TOOL}.git
cd ${TOOL}

## Clean out earlier vendoring
rm -rf Godeps vendor

## Get govendor
go get github.com/kardianos/govendor

## Init
govendor init

## Fetch deps
echo "Fetching deps, will take some time..."
govendor fetch +missing

echo "Done; to commit run \n\ncd ${GOPATH}/src/github.com/hashicorp/${TOOL}\n"

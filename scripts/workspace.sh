#!/bin/sh
# go.work for CI: the core (this checkout), and the firewall module, with this checkout standing in for the core
# version the firewall requires (that tag does not exist before the release). Run from the repository root.
set -eu
version=$(sed -n 's/^const Version = "\(.*\)"$/\1/p' version.go)
[ -n "$version" ] || { echo "workspace.sh: no version in version.go" >&2; exit 1; }
go work init . firewall
go work edit -replace "github.com/ZaeemSattar/revokegpt-go@v$version=."

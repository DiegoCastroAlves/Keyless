#!/usr/bin/env bash
# Builds the Arch Linux package from the checked-out commit, inside an
# archlinux:base-devel container. Usage: build-arch-package.sh <version>
#
# CARGO_HOME and CARGO_TARGET_DIR (set by the workflow) point outside the
# makepkg directory so they can be cached between runs. The package lands in
# /tmp/arch.
set -euo pipefail

version="$1"
git config --global --add safe.directory "$GITHUB_WORKSPACE"
id builder > /dev/null 2>&1 || useradd -m builder

rm -rf /tmp/arch
mkdir -p /tmp/arch "$CARGO_HOME" "$CARGO_TARGET_DIR"
cp packaging/arch/PKGBUILD /tmp/arch/
sed -i "s/^pkgver=.*/pkgver=$version/" /tmp/arch/PKGBUILD
# makepkg uses this local copy of the source instead of downloading it.
git archive --format=tar.gz --prefix="Keyless-$version/" -o "/tmp/arch/keyless-$version.tar.gz" HEAD
chown -R builder /tmp/arch "$CARGO_HOME" "$CARGO_TARGET_DIR"

cd /tmp/arch
sudo -u builder --preserve-env=CARGO_HOME,CARGO_TARGET_DIR makepkg --noconfirm

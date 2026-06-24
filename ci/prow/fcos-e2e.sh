#!/bin/bash
set -xeuo pipefail

# Prow jobs don't support adding emptydir today
export COSA_SKIP_OVERLAY=1
# And suppress depcheck since we didn't install via RPM
export COSA_SUPPRESS_DEPCHECK=1
# The overlay ostree may be linked against a different Fedora than the cosa
# container (e.g. buildroot is F44 but cosa is F43), so this can fail with
# missing sonames. The actual compose uses overrides/rootfs/ which targets
# the correct Fedora version.
ostree --version || echo "NOTE: ostree --version failed in container (expected if buildroot != cosa Fedora version)"
cd $(mktemp -d)
cosa init https://github.com/coreos/fedora-coreos-config/
rsync -rlv /cosa/component-install/ overrides/rootfs/
cosa fetch
# For composefs
echo 'rootfs: "ext4verity"' >> src/config/image.yaml
cosa build
# For now, Prow just runs the composefs tests, since Jenkins covers the others
#cosa kola run 'ext.ostree.destructive-rs.composefs*'

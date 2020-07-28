#!/bin/bash
set +x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Clean up any past builds
rm -rf  $DIR/../build || true

# Create and cd into build directory
mkdir $DIR/../build && cd $DIR/../build

# Configuration to build a redistributable SDK package
cmake -G 'Unix Makefiles' .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DLVI_MITIGATION=ControlFlow -DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin

# Create a redistributable OE SDK package
cpack -G DEB

# Create a redistributable OE Host Verificaiton package
cpack -G DEB -D CPACK_DEB_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY

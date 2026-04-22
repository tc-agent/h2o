#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

pushd $SRC/h2o

# Copy new fuzz harnesses into the h2o source tree.
cp $SRC/driver_hpack.cc fuzz/driver_hpack.cc
cp $SRC/driver_qpack.cc fuzz/driver_qpack.cc

# Patch CMakeLists.txt to build the new harnesses alongside the existing ones.
python3 - <<'EOF'
import sys

with open('CMakeLists.txt', 'r') as f:
    content = f.read()

if 'h2o-fuzzer-hpack' in content:
    print('CMakeLists.txt already patched, skipping')
    sys.exit(0)

if 'ENDIF (BUILD_FUZZER)' not in content:
    print('ERROR: could not find ENDIF (BUILD_FUZZER) in CMakeLists.txt', file=sys.stderr)
    sys.exit(1)

new_targets = (
    '    ADD_EXECUTABLE(h2o-fuzzer-hpack fuzz/driver_hpack.cc)\n'
    '    ADD_EXECUTABLE(h2o-fuzzer-qpack fuzz/driver_qpack.cc)\n'
    '    TARGET_LINK_LIBRARIES(h2o-fuzzer-hpack libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})\n'
    '    TARGET_LINK_LIBRARIES(h2o-fuzzer-qpack libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})\n'
    '\n'
    'ENDIF (BUILD_FUZZER)'
)
content = content.replace('ENDIF (BUILD_FUZZER)', new_targets, 1)
with open('CMakeLists.txt', 'w') as f:
    f.write(content)
print('CMakeLists.txt patched successfully')
EOF

cmake -DBUILD_FUZZER=ON -DOSS_FUZZ=ON -DOPENSSL_USE_STATIC_LIBS=TRUE .
make
cp ./h2o-fuzzer-* $OUT/

zip -jr $OUT/h2o-fuzzer-http1_seed_corpus.zip $SRC/h2o/fuzz/http1-corpus
zip -jr $OUT/h2o-fuzzer-http2_seed_corpus.zip $SRC/h2o/fuzz/http2-corpus
zip -jr $OUT/h2o-fuzzer-http3_seed_corpus.zip $SRC/h2o/fuzz/http3-corpus
zip -jr $OUT/h2o-fuzzer-url_seed_corpus.zip $SRC/h2o/fuzz/url-corpus
zip -jr $OUT/h2o-fuzzer-hpack_seed_corpus.zip $SRC/h2o-fuzzer-hpack-seeds
zip -jr $OUT/h2o-fuzzer-qpack_seed_corpus.zip $SRC/h2o-fuzzer-qpack-seeds

cp $SRC/*.options $SRC/h2o/fuzz/*.dict $OUT/
popd

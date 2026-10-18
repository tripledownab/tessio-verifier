# Builds libmdoc.so, Google's Longfellow ZK mdoc prover and verifier, from source at a pinned commit.
# The verifier package loads it to check zero knowledge age proofs. Nothing prebuilt is downloaded: the
# library is compiled here, and Longfellow's own mdoc test suite must pass before it is copied out.
# It lives under src/ so the conformance record, which hashes src/, covers the native library too.
# debian:bookworm-20250929-slim, pinned by digest.
FROM debian@sha256:7e490910eea2861b9664577a96b54ce68ea3e02ce7f51d89cb0103a6f9c386e0 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang cmake make git ca-certificates \
      libssl-dev libzstd-dev zlib1g-dev libgtest-dev libbenchmark-dev \
 && rm -rf /var/lib/apt/lists/*

# v0.9 of github.com/longfellow-zk/longfellow-zk. The commit, not the tag, is what is trusted: a tag can move.
ARG LONGFELLOW_COMMIT=fe83ec6c4efa5f98bc2439c8b06e5eccd153aca0
WORKDIR /src
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/longfellow-zk/longfellow-zk "$LONGFELLOW_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$LONGFELLOW_COMMIT"

# One upstream change on top of v0.9, until a release carries it: longfellow-zk pull request #207 (merged
# into main as d9d8d6a), which sizes each decompressed circuit from its zstd frame header instead of the
# 130 MB bound and frees the verifier's copy once it is parsed. It lowers the verifier's peak memory and
# changes no behaviour. Backported unchanged except for v0.9's name for one class (CircuitRep, later
# renamed CircuitReader). Drop this step, and the file, when the pinned commit is a release that has it.
COPY longfellow-pr207-reserve-actual-size.patch /longfellow-pr207.patch
RUN git apply /longfellow-pr207.patch

# Position independent code, so the static archive can become a shared library.
RUN CXX=clang++ CC=clang cmake -D CMAKE_BUILD_TYPE=Release -D CMAKE_POSITION_INDEPENDENT_CODE=ON \
      -S lib -B build \
 && cmake --build build --target mdoc_static mdoc_zk_test -j "$(nproc)" \
 && ./build/circuits/mdoc/mdoc_zk_test

# Only the functions the package calls are exported, so the library's internals cannot clash with other
# native code in the same process.
COPY exports.map /exports.map
RUN mkdir /out \
 && clang++ -shared -o /out/libmdoc.so -Wl,--version-script=/exports.map \
      -Wl,--whole-archive build/circuits/mdoc/libmdoc_static.a -Wl,--no-whole-archive \
      -lcrypto -lzstd -lz \
 && nm -D /out/libmdoc.so | grep -q " T run_mdoc_verifier$" \
 && nm -D /out/libmdoc.so | grep -q " T find_zk_spec$" \
 && nm -D /out/libmdoc.so | grep -q " T circuit_id$" \
 && nm -D /out/libmdoc.so | grep -q " T _ZN6proofs13set_log_levelENS_8LogLevelE$"

FROM scratch
COPY --from=build /out/libmdoc.so /libmdoc.so

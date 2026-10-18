# Third party notices

This package contains software and data from Longfellow ZK.

- `runtimes/linux-x64/native/libmdoc.so` is built from github.com/longfellow-zk/longfellow-zk at commit
  fe83ec6c4efa5f98bc2439c8b06e5eccd153aca0 (v0.9), by `native/Dockerfile` in this package's source, with one
  upstream change applied: longfellow-zk pull request #207, which lowers the verifier's peak memory. It modifies
  `lib/circuits/mdoc/mdoc_circuit_id.cc`, `lib/circuits/mdoc/mdoc_decompress.cc` and
  `lib/circuits/mdoc/mdoc_zk.cc`, and is `native/longfellow-pr207-reserve-actual-size.patch` in the same source.
- The circuits embedded in `Tessio.Verifier.Core.Mdoc.Zk.dll` are files from the same commit, under
  `lib/circuits/mdoc/circuits`.

Copyright 2025 Google LLC. Licensed under the Apache License, Version 2.0; a copy is in `LICENSE-Apache-2.0.txt`
in this package. You may not use these files except in compliance with the License. Unless required by applicable
law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

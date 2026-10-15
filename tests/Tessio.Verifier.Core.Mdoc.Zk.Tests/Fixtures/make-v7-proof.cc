// Makes a v7 Longfellow proof of one attribute from Longfellow's own EU age verification example mdoc, so the
// verifier's v7 path can be tested with a genuine proof. Prints the inputs; writes the proof.
//
// longfellow-libzk-v1_7_1_4151_4096_8d07... with mdoc_tests[15] produced longfellow-mdoc-tests-15-v7-proof.bin.
// libmdoc_static.a exists only in the build stage of src/Tessio.Verifier.Core.Mdoc.Zk/native/Dockerfile, so
// build there: docker build --target build, then run that image with this file and the v7 circuit mounted at /w
// and, from /src,
//   clang++ -std=c++17 -O2 -Ilib /w/make-v7-proof.cc build/circuits/mdoc/libmdoc_static.a -lcrypto -lzstd -lz -o prove
//   ./prove 15 /w/<v7 circuit file> 8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121 /w/<out>
// A proof is randomised, so a rerun writes different bytes that verify the same way.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/mdoc/mdoc_examples.h"
#include "circuits/mdoc/mdoc_test_attributes.h"

using namespace proofs;

int main(int argc, char** argv) {
  if (argc != 5) { fprintf(stderr, "usage: prove <mdoc_tests index> <circuit file> <circuit hash> <out>\n"); return 2; }
  const int index = atoi(argv[1]);
  if (index < 0 || (size_t)index >= sizeof(mdoc_tests) / sizeof(mdoc_tests[0])) {
    fprintf(stderr, "no mdoc_tests[%d]\n", index);
    return 2;
  }
  FILE* f = fopen(argv[2], "rb");
  if (!f) { perror(argv[2]); return 2; }
  std::vector<uint8_t> circuit;
  int c;
  while ((c = fgetc(f)) != EOF) circuit.push_back((uint8_t)c);
  fclose(f);
  const ZkSpecStruct* spec = find_zk_spec("longfellow-libzk-v1", argv[3]);
  if (!spec) { printf("no spec\n"); return 3; }
  const MdocTests* t = &mdoc_tests[index];
  RequestedAttribute attrs[1] = {test::europa_age_over_18};
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  MdocProverErrorCode p = run_mdoc_prover(circuit.data(), circuit.size(), t->mdoc, t->mdoc_size,
      t->pkx.as_pointer, t->pky.as_pointer, t->transcript, t->transcript_size, attrs, 1,
      (const char*)t->now, &proof, &proof_len, spec);
  printf("prover rc=%d proof_len=%zu\n", (int)p, proof_len);
  if (p != MDOC_PROVER_SUCCESS) return 1;
  MdocVerifierErrorCode v = run_mdoc_verifier(circuit.data(), circuit.size(), t->pkx.as_pointer,
      t->pky.as_pointer, t->transcript, t->transcript_size, attrs, 1, (const char*)t->now, proof,
      proof_len, t->doc_type, spec);
  printf("verifier rc=%d\n", (int)v);
  printf("pkx=%s\npky=%s\nnow=%.20s\ndoctype=%s\nnamespace=%.*s\ntranscript=", t->pkx.as_pointer,
      t->pky.as_pointer, (const char*)t->now, t->doc_type, (int)attrs[0].namespace_len,
      (const char*)attrs[0].namespace_id);
  for (size_t i = 0; i < t->transcript_size; i++) printf("%02x", t->transcript[i]);
  printf("\n");
  FILE* o = fopen(argv[4], "wb");
  if (!o) { perror(argv[4]); return 2; }
  fwrite(proof, 1, proof_len, o);
  fclose(o);
  free(proof);
  return v == MDOC_VERIFIER_SUCCESS ? 0 : 4;
}

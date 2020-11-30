// RUN: %clang_dfsan %s -o %t
// RUN: DFSAN_OPTIONS=dump_labels_at_exit=/dev/stdout %run %t 2>&1 | FileCheck %s
// RUN: DFSAN_OPTIONS=dump_labels_at_exit=/dev/stdout not %run %t c 2>&1 | FileCheck %s --check-prefix=CHECK-OOL
// RUN: DFSAN_OPTIONS=dump_labels_at_exit=/dev/stdout not %run %t u 2>&1 | FileCheck %s --check-prefix=CHECK-OOL

// Tests that labels are properly dumped at program termination.

// clang -fsanitize=dataflow dump_labels.c

// angora's args
// clang /home/jordan/develop/chunk-fuzzer-pass/test/loopTest.bc -o loopTest.tt -Xclang -load -Xclang ./pass/libUnfoldBranchPass.so -Xclang -load -Xclang ./pass/libAngoraPass.so -mllvm -TrackMode -mllvm -angora-dfsan-abilist=./rules/angora_abilist.txt -mllvm -angora-dfsan-abilist=./rules/dfsan_abilist.txt -mllvm -angora-exploitation-list=./rules/exploitation_list.txt -Xclang -load -Xclang ./pass/libDFSanPass.so -mllvm -angora-dfsan-abilist2=./rules/angora_abilist.txt -mllvm -angora-dfsan-abilist2=./rules/dfsan_abilist.txt -pie -fpic -Qunused-arguments -g -O3 -funroll-loops -Wl,--whole-archive ./lib/libdfsan_rt-x86_64.a -Wl,--no-whole-archive -Wl,--dynamic-list=./lib/libdfsan_rt-x86_64.a.syms ./lib/libruntime.a ./lib/libDFSanIO.a -lstdc++ -lrt -Wl,--no-as-needed -Wl,--gc-sections -ldl -lpthread -lm 
 
//clang -I /home/jordan/develop/chunk-fuzzer-pass/dfsan_rt/ \
-I /home/jordan/develop/chunk-fuzzer-pass/include/ \
-Xclang -load -Xclang ./pass/libDFSanPass.so \
-mllvm -chunk-dfsan-abilist=./rules/angora_abilist.txt \
-mllvm -chunk-dfsan-abilist=./rules/dfsan_abilist.txt \
-pie -fpic -Qunused-arguments -g -O3 -funroll-loops \
-Wl,--whole-archive ./lib/libdfsan_rt-x86_64.a -Wl,--no-whole-archive \
-Wl,--dynamic-list=./lib/libdfsan_rt-x86_64.a.syms \
-lstdc++ -lrt -Wl,--no-as-needed -Wl,--gc-sections \
-ldl -lpthread -lm \
/home/jordan/develop/chunk-fuzzer-pass/test/dump_labels.c -o dump_labels

//#include "../dfsan_rt/dfsan_interface.h"
#include <sanitizer/dfsan_interface.h>
#include <assert.h>
#include <stdio.h>

int main(int argc, char** argv) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label("i", 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  int j = 2;
  dfsan_label j_label = dfsan_create_label("j", 0);
  dfsan_set_label(j_label, &j, sizeof(j));

  int k = 3;
  dfsan_label k_label = dfsan_create_label("k", 0);
  dfsan_set_label(k_label, &k, sizeof(k));

  dfsan_label ij_label = dfsan_get_label(i + j);
  dfsan_label ijk_label = dfsan_get_label(i + j + k);

  fprintf(stderr, "i %d j %d k %d ij %d ijk %d\n", i_label, j_label, k_label,
          ij_label, ijk_label);

  // CHECK: 1 0 0 i
  // CHECK: 2 0 0 j
  // CHECK: 3 0 0 k
  // CHECK: 4 1 2
  // CHECK: 5 3 4

  if (argc > 1) {
    // Exhaust the labels.
    unsigned long num_labels = 1 << (sizeof(dfsan_label) * 8);
    for (unsigned long i =  ijk_label + 1; i < num_labels - 2; ++i) {
      dfsan_label l = dfsan_create_label("l", 0);
      assert(l == i);
    }

    // Consume the last available label.
    dfsan_label l = dfsan_union(5, 6);
    assert(l == num_labels - 2);

    // Try to allocate another label (either explicitly or by unioning two
    // existing labels), but expect a crash.
    if (argv[1][0] == 'c') {
      l = dfsan_create_label("l", 0);
    } else {
      l = dfsan_union(6, 7);
    }

    // CHECK-OOL: FATAL: DataFlowSanitizer: out of labels
    // CHECK-OOL: 1 0 0 i
    // CHECK-OOL: 2 0 0 j
    // CHECK-OOL: 3 0 0 k
    // CHECK-OOL: 4 1 2
    // CHECK-OOL: 5 3 4
    // CHECK-OOL: 6 0 0
    // CHECK-OOL: 65534 5 6
    // CHECK-OOL: 65535 0 0 <init label>
  }

  return 0;
}

/*
clang -I ../include -fsanitize=dataflow -Xclang -load -Xclang ../install/pass/libDFSanPass.so dfsan_test.c

clang -I /home/jordan/develop/chunk-fuzzer-pass/dfsan_rt/ -I /home/jordan/develop/chunk-fuzzer-pass/include/ -L /home/jordan/develop/chunk-fuzzer-pass/install/lib/ dfsan_test.c -ldfsan_rt-x86_64 -lpthread -lrt -lstdc++ -ldl


*/

#include <sanitizer/dfsan_interface.h>
//#include "../dfsan_rt/dfsan_interface.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label("i", 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  int j = 2;
  dfsan_label j_label = dfsan_create_label("j", 0);
  dfsan_set_label(j_label, &j, sizeof(j));

  int k = 3;
  dfsan_label k_label = dfsan_create_label("k", 0);
  dfsan_set_label(k_label, &k, sizeof(k));

  // printf("%d",*dfsan_get_label_info(i_label));

  // printf("%d",*dfsan_get_label_info(j_label));

  // printf("%d",*dfsan_get_label_info(k_label));


  dfsan_label ij_label = dfsan_get_label(i + j);
  assert(dfsan_has_label(ij_label, i_label));
  assert(dfsan_has_label(ij_label, j_label));
  assert(dfsan_has_label(ij_label, k_label));

  dfsan_label ijk_label = dfsan_get_label(i + j + k);
  assert(dfsan_has_label(ijk_label, i_label));
  assert(dfsan_has_label(ijk_label, j_label));
  assert(dfsan_has_label(ijk_label, k_label));

  return 0;
}

// RUN: %clang_dfsan %s -o %t && %run %t
// RUN: %clang_dfsan -mllvm -dfsan-args-abi %s -o %t && %run %t

// Tests that labels are propagated through loads and stores.

//test-clang basic.c
#include "../dfsan_rt/dfsan_interface.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label(0);
  dfsan_set_label(i_label, &i, sizeof(i));

  dfsan_label new_label = dfsan_get_label(i);
  assert(i_label == new_label);

  dfsan_label read_label = dfsan_read_label(&i, sizeof(i));
  assert(i_label == read_label);

  dfsan_label j_label = dfsan_create_label(0);
  dfsan_add_label(j_label, &i, sizeof(i));

  read_label = dfsan_read_label(&i, sizeof(i));
  printf("i: %d,\n new: %d,\n j: %d,\n read: %d\n", i_label, new_label,read_label,j_label);
  // assert(dfsan_has_label(read_label, i_label));
  // assert(dfsan_has_label(read_label, j_label));

  return 0;
}

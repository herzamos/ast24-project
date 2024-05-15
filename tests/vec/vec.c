#include "marker.h"
#include <immintrin.h>

static int add_function(int *a, int *b, int *c, int n) {
  for (int i = 0; i < n; ++i) {
    c[i] = a[i] + b[i];
  }
  return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  markerf();
  add_function(a, b, c, LEN);
  markerf();
  return 0;
}
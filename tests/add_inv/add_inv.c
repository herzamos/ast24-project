#include "marker.h"
// #define LEN 64
#define LEN 4

static __attribute__((optimize("O0"))) int add_function(int *a, int *b, int *c, int n) {
  for (int i = 0; i < n; ++i) {
    if (i & 1) {
      c[i] = a[i] + b[i];
    } else {
      c[i] = b[i] + a[i];
    }
  }
  return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  int a[LEN] = { 0 };
  int b[LEN] = { 0 }; 
  int c[LEN] = { 0 }; 
  markerf();
  add_function(a, b, c, LEN);
  markerf();
  return 0;
}

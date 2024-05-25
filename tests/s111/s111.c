#include "marker.h"
// #define LEN 64
#define LEN 4

static __attribute__((optimize("O0"))) int s111(int *a, int *b, int n) {
  for (int i = 1; i < LEN; i += 2) {
    a[i] = a[i - 1] + b[i];
  }
  return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  int a[LEN] = { 0 };
  int b[LEN] = { 0 }; 
  markerf();
  s111(a, b, LEN);
  markerf();
  return 0;
}

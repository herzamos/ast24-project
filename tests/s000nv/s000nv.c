#include "marker.h"
// #define LEN 64
#define LEN 4

static int __attribute__((optimize("O0"))) s000(int *a, int *b, int n) {
  for (int i = 0; i < n; ++i) {
    if (i == 1) continue;
    a[i] = b[i] + 1;
  }
  return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  int a[LEN] = { 0 };
  int b[LEN] = { 0 }; 
  markerf();
  s000(a, b, LEN);
  markerf();
  return 0;
}

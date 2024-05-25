#include "marker.h"
// #define LEN 64
#define LEN 10

static int s116(int *a, int *b, int n) {
  for (int i = 0; i < LEN - 3; i += 3) {
            a[i] = a[i + 1] * a[i];
            a[i + 1] = a[i + 2] * a[i + 1];
            a[i + 2] = a[i + 3] * a[i + 2];
            // a[i + 3] = a[i + 4] * a[i + 3];
            // a[i + 4] = a[i + 5] * a[i + 4];
        }
  return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  int a[LEN] = { 0 };
  int b[LEN] = { 0 }; 
  markerf();
  s116(a, b, LEN);
  markerf();
  return 0;
}

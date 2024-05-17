#include "marker.h"
#include <immintrin.h>
#include <stdio.h>

#define LEN 4

static int add_function(const double *a, const double *b, double *c, int n) {
  __m256d t = _mm256_loadu_pd(a);
  __m256d s = _mm256_loadu_pd(b);
  __m256d res = _mm256_add_pd(t, s);
  _mm256_storeu_pd(c, res);
  return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
  double a[4] = {1.0, 2.0, 3.0, 4.0};
  double b[4] = {5.0, 6.0, 8.0, 412.0};
  double c[4] = {1.0, 2.0, 3.0, 4.0};
  markerf();
  add_function(a, b, c, LEN);
  markerf();
  return 0;
}
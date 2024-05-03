#include "marker.h"
// #define LEN 64
#define LEN 3

static int add_function(volatile int *a, volatile int *b, volatile int *c, int n) {
    if (n) {
        c[0] = a[0] + b[0];
        add_function(&a[1], &b[1], &c[1], n-1);
    }
    return 0;
}

int main(int argc, char **argv) {
  volatile int a[LEN] = { 0 };
  volatile int b[LEN] = { 0 }; 
  volatile int c[LEN] = { 0 }; 
  markerf();
  add_function(a, b, c, LEN);
  markerf();
  return 0;
}

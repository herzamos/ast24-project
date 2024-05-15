#include "marker.h"
// #define LEN 64
#define LEN 4

static int fold(int *a, volatile int *b, int *c, int n) {
    // int acc = 0;
    *b = 0;
    for (int i = 0; i < n; ++i) {
        *b += a[i];
    }
    *c = *b;
    return 0;
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
    int a[LEN] = { 0 };
    int b;
    int c;
    markerf();
    fold(a, &b, &c, LEN);
    markerf();
    return 0;
}

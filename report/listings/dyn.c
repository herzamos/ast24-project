#include <stdint.h>
void dyn(float *a, float *b, uint8_t *c, unsigned int n) {
    for (int i = 0; i < n; ++i) {
        if (c[i]) {
            a[i] = 2 * b[i];
        } else {

            a[i] = 4 * b[i];
        }
    }
}
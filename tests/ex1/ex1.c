#include "marker.h"
#include <stdint.h>
#include <stdbool.h>
#define LEN 1

void ex1(int8_t *v, int8_t x, const uint64_t *bits, unsigned n)
{
    int num_words = (n + 64 - 1) / 64; // round up to nearest quad - word
    for (int i = 0; i < num_words; ++i)
    {
        const uint64_t word = bits[i];
        for (int j = 0; j < 64; ++j)
        {
            v[i * 64 + j] += x * (bool)(word & (1UL << j));
        }
    }
}

int __attribute__((optimize("O0"))) main(int argc, char **argv) {
    volatile int8_t a[LEN * 64] = { 0 };
    volatile uint64_t bits[LEN] = { 1 };
    markerf();

    ex1(a,12, bits, LEN * 64);

    markerf();
    return 0;
}
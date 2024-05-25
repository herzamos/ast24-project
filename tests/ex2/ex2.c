#include "marker.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define LEN 1

void __attribute__((optimize("O0"))) cvt_8_32(volatile uint32_t *op, volatile uint8_t const *ints)
{
    uint32_t out[16];
    uint8_t in[16];
    memcpy(in, ints, sizeof(in));
    for (int i = 0; i < 16; ++i)
    {
        out[i] = in[i];
    }
    memcpy(op, out, sizeof(out));
}

int __attribute__((optimize("O0"))) main(int argc, char **argv)
{
    volatile uint8_t ints[16] = {0};
    volatile uint32_t op[16] = {1};
    markerf();

    cvt_8_32(op, ints);

    markerf();
    return 0;
}
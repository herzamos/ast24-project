#include <stdint.h>

void ex1(int8_t *v, int8_t x, const uint64_t *bits, unsigned n) {
  int num_words = (n + 64 - 1) / 64; // round up to nearest quad-word
  for (int i = 0; i < n; ++i) {
    const uint64_t word = bits[i];
    for (int j = 0; j < 64; ++j) {
      v[i * 64 + j] += x * (bool)(word & (1UL << j));
    }
  }
}
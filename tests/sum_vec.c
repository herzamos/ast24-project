int main(int argc, char **argv) {
  return 0;
}

void sum_vec(char *restrict a, char *restrict b, int n) {
  for (int i = 0; i < n; ++i) {
    a[i] += b[i];
  }
}

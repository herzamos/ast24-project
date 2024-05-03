// #define LEN 64
#define LEN 3

static int add_function(volatile int *a, volatile int *b, volatile int *c, int n) {
  for (int i = 0; i < n; ++i) {
    c[i] = a[i] + b[i];
  }
  for (int i = 0; i < n; ++i) {
    c[i] = a[i] + b[i];
  }
  return 0;
}

int main(int argc, char **argv) {
  volatile int a[LEN] = { 0 };
  volatile int b[LEN] = { 0 }; 
  volatile int c[LEN] = { 0 }; 
  int ret = add_function(a, b, c, LEN);
  return ret;
}
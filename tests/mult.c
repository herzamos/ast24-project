#define LEN 64
int main(int argc, char **argv) {
  volatile int a[LEN] = { 0 };
  volatile int b[LEN] = { 0 }; 
  volatile int c[LEN] = { 0 }; 
  
  for (int i = 0; i < LEN; ++i) {
    c[i] = a[i] * b[i];
  }
  return 0; 
}

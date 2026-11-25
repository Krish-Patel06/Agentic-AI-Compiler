// Untrusted high-performance numerical kernel
extern "C" void compute_dot_product(const float* a, const float* b, float* out, int n) {
    float sum = 0.0f;
    for (int i = 0; i < n; ++i) {
        sum += a[i] * b[i];
    }
    *out = sum;
}

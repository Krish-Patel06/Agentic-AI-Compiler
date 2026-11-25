
extern "C" float process_trade_signals(const float* prices, const float* weights, int n) {
    float cumulative_signal = 0.0f;
    for (int i = 0; i < n; ++i) {
        cumulative_signal += prices[i] * weights[i];
    }
    return cumulative_signal;
}

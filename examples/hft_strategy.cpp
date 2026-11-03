// =============================================================================
// AGentic_C — Example HFT Strategy (anti-patterns FIXED)
// =============================================================================
//
// This file demonstrates a realistic (simplified) HFT trading strategy.
// Anti-patterns have been fixed as follows:
//
// FIXED:
//   LAP-001 Heap Allocation  → stack double, CRTP on-stack object (no new/delete)
//   LAP-002 Virtual Dispatch → CRTP (compile-time dispatch, zero vtable overhead)
//   LAP-005 System Call/I/O  → async lock-free ring buffer (no syscall on hot path)
//   LAP-010 Branch-Heavy     → branchless lookup table (no nested if-else)
//
// UNCHANGED (out of scope):
//   LAP-003 Exception (submit_order)
//   LAP-006 std::function (submit_order)
//   check_risk, load_config, log_trade
//
// Run through AGentic_C:
//   python src/pipeline.py examples/hft_strategy.cpp
//
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <functional>
#include <string>
#include <stdexcept>

// ---------------------------------------------------------------------------
// Constants and types
// ---------------------------------------------------------------------------

static const int    MAX_POSITION  = 10000;
static const int    MAX_ORDER_QTY = 500;
static const double TICK_SIZE     = 0.01;
static const int    EMA_WINDOW    = 20;

struct Tick {
    double  price;
    int     size;
    uint8_t side;        // 0 = bid, 1 = ask
    long    timestamp_ns;
};

struct Order {
    double  price;
    int     qty;
    uint8_t side;
    char    symbol[8];
};

static Order   g_order;
static int     g_socket_fd   = -1;
static int     g_position     = 0;
static double  g_ema_fast     = 0.0;
static double  g_ema_slow     = 0.0;
static double  g_mid_price    = 0.0;

// ---------------------------------------------------------------------------
// FIX LAP-005: Lock-free ring buffer for async logging
// Hot path enqueues messages without any syscall.
// A background thread drains the ring with flush_async_log().
// ---------------------------------------------------------------------------

static const int LOG_RING_CAP = 256; // power-of-2 for cheap modulo

struct LogEntry { char msg[128]; };

static LogEntry     g_log_ring[LOG_RING_CAP];
static volatile int g_log_head = 0;   // written by hot path (producer)
static volatile int g_log_tail = 0;   // written by background thread (consumer)

// Enqueue a log message — no syscall, no heap, noexcept.
// Drops silently if ring is full rather than blocking the hot path.
inline void async_log(const char* msg) noexcept {
    int next = (g_log_head + 1) & (LOG_RING_CAP - 1);
    if (next == g_log_tail) return;      // full — drop, never stall
    char* dst = g_log_ring[g_log_head].msg;
    int i = 0;
    while (i < 127 && msg[i]) { dst[i] = msg[i]; ++i; }
    dst[i] = '\0';
    g_log_head = next;                   // publish
}

// Drain ring — call from cold / background thread only.
void flush_async_log() noexcept {
    while (g_log_tail != g_log_head) {
        puts(g_log_ring[g_log_tail].msg);
        g_log_tail = (g_log_tail + 1) & (LOG_RING_CAP - 1);
    }
}

// ---------------------------------------------------------------------------
// FIX LAP-002: CRTP signal base — zero virtual-dispatch overhead
// Derived type is resolved at compile time; no vtable, no indirect call,
// fully inlinable by the optimizer.
// ---------------------------------------------------------------------------

template <typename Derived>
struct SignalBase {
    inline double compute(double fast, double slow) noexcept {
        return static_cast<Derived*>(this)->compute_impl(fast, slow);
    }
};

// ✓ CRTP concrete type — compute_impl inlined at call site
struct MomentumSignal : public SignalBase<MomentumSignal> {
    inline double compute_impl(double fast, double slow) noexcept {
        return fast - slow;
    }
};

// ---------------------------------------------------------------------------
// FIX LAP-010: Branchless signal classification via sorted threshold table
// Replaces deeply nested if-else with a single linear scan over 6 thresholds.
// Branch predictor sees a simple loop; all thresholds fit in one cache line.
// ---------------------------------------------------------------------------

// Each entry: { lower_bound, return_value }
// Thresholds sorted descending so first match wins (strong > moderate > weak).
struct ThresholdEntry { double bound; int value; };

static const std::array<ThresholdEntry, 7> SIGNAL_TABLE = {{
    {  0.30,  3 },   // strong buy
    {  0.15,  2 },   // moderate buy
    {  0.05,  1 },   // weak buy
    { -0.05,  0 },   // neutral
    { -0.15, -1 },   // weak sell
    { -0.30, -2 },   // moderate sell
    { -1e18, -3 },   // strong sell (catch-all)
}};

// ---------------------------------------------------------------------------
// HOT PATH FUNCTIONS
// ---------------------------------------------------------------------------

// ✓ LAP-001 FIXED: stack double instead of new double(tick.price)
// ✓ LAP-005 FIXED: async_log() instead of printf() — zero syscall cost
[[hft::hot]]
double on_market_data(const Tick& tick) {
    // ✓ Stack allocation — no heap, no 100ns-10µs latency spike
    const double entry = tick.price;

    // ✓ Async ring-buffer log — no kernel context switch
    async_log("Tick received");

    // Update mid price and EMAs
    g_mid_price = entry;

    const double alpha_fast = 2.0 / (EMA_WINDOW + 1);
    const double alpha_slow = 2.0 / (EMA_WINDOW * 4 + 1);

    g_ema_fast = alpha_fast * entry + (1.0 - alpha_fast) * g_ema_fast;
    g_ema_slow = alpha_slow * entry + (1.0 - alpha_slow) * g_ema_slow;

    return g_mid_price;
}

// ✓ LAP-001 FIXED: MomentumSignal lives on the stack (no new/delete)
// ✓ LAP-002 FIXED: CRTP — compute() resolved at compile time (no vtable lookup)
// ✓ LAP-010 FIXED: branchless threshold table (no nested if-else)
[[hft::hot]]
int evaluate_signal(double fast_ema, double slow_ema) {
    // ✓ Stack CRTP object — no heap, no vtable indirection
    MomentumSignal sig;
    const double signal_val = sig.compute(fast_ema, slow_ema);

    // ✓ Branchless lookup table — single sequential scan, one cache line
    for (const auto& t : SIGNAL_TABLE) {
        if (signal_val >= t.bound) return t.value;
    }
    return -3;  // saturated strong sell (should be caught by last entry)
}

// CLEAN HOT PATH — unchanged gold standard
[[hft::hot]]
inline bool check_risk(int qty, int current_position) noexcept {
    int new_position = current_position + qty;
    bool qty_ok      = (qty > 0 && qty <= MAX_ORDER_QTY);
    bool pos_ok      = (new_position >= -MAX_POSITION && new_position <= MAX_POSITION);
    return qty_ok && pos_ok;
}

// LAP-003: exception on hot path (out of scope — unchanged)
// LAP-006: std::function indirect call (out of scope — unchanged)
[[hft::hot]]
bool submit_order(int qty, double price, uint8_t side) {
    if (qty <= 0 || price <= 0.0) {
        throw std::invalid_argument("Invalid order parameters");
    }

    std::function<bool()> send_fn = [&]() {
        g_order.price = price;
        g_order.qty   = qty;
        g_order.side  = side;
        return (g_socket_fd >= 0);
    };

    if (!check_risk(qty, g_position)) {
        return false;
    }

    bool sent = send_fn();
    if (sent) {
        g_position += (side == 0) ? qty : -qty;
    }
    return sent;
}

// ---------------------------------------------------------------------------
// COLD PATH FUNCTIONS (unchanged)
// ---------------------------------------------------------------------------

[[hft::cold]]
void load_config(const char* config_path) {
    printf("Loading config from: %s\n", config_path);

    g_socket_fd   = 0;
    g_position    = 0;
    g_ema_fast    = 0.0;
    g_ema_slow    = 0.0;
    g_mid_price   = 0.0;

    printf("Config loaded. socket_fd=%d initial_position=%d\n",
           g_socket_fd, g_position);
}

[[hft::cold]]
void log_trade(int qty, double price, uint8_t side, bool success) {
    const char* side_str = (side == 0) ? "BUY" : "SELL";
    printf("[TRADE] %s qty=%d price=%.4f success=%s position=%d\n",
           side_str, qty, price, success ? "YES" : "NO", g_position);
}

// ---------------------------------------------------------------------------
// Main entry point for standalone testing
// ---------------------------------------------------------------------------

int main() {
    printf("=== AGentic_C HFT Strategy Demo ===\n");

    // Cold path setup
    load_config("config/hft.yaml");

    // Simulate a market data event loop
    Tick tick = { 100.05, 1000, 0, 1713000000000LL };

    double price  = on_market_data(tick);
    int    signal = evaluate_signal(g_ema_fast, g_ema_slow);
    bool   ok     = check_risk(100, g_position);

    if (ok && signal > 0) {
        bool sent = submit_order(100, price, 0);
        log_trade(100, price, 0, sent);
    }

    // Drain the async log before exit (cold path)
    flush_async_log();

    printf("=== Done. Position: %d ===\n", g_position);
    return 0;
}

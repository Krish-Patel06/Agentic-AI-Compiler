#pragma once
#include <string>
#include <vector>
#include <set>

struct IRScanResult {
    bool is_valid{false};
    size_t instruction_count{0};
    size_t function_count{0};
    size_t basic_block_count{0};
    std::string sha256_fingerprint;
    std::vector<std::string> violations;
};

class IRScanner {
public:
    static IRScanResult scan_file(const std::string& ir_filepath);
    static IRScanResult scan_string(const std::string& ir_content);
};

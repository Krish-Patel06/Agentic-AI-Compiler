#include "ir_scanner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>

IRScanResult IRScanner::scan_string(const std::string& ir_content) {
    IRScanResult res;
    if (ir_content.empty()) {
        res.violations.push_back("Empty IR content");
        return res;
    }

    // 1. Inline assembly check
    if (ir_content.find("module asm") != std::string::npos ||
        ir_content.find("call ") != std::string::npos && ir_content.find("asm ") != std::string::npos) {
        res.violations.push_back("Prohibited inline assembly detected");
    }

    // 2. Forbidden intrinsics
    const std::vector<std::string> forbidden = {
        "llvm.trap", "llvm.debugtrap", "llvm.frameaddress", "llvm.returnaddress"
    };
    for (const auto& intr : forbidden) {
        if (ir_content.find(intr) != std::string::npos) {
            res.violations.push_back("Forbidden intrinsic detected: " + intr);
        }
    }

    std::istringstream stream(ir_content);
    std::string line;
    bool in_func = false;

    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == ';') continue;

        if (line.rfind("define ", 0) == 0) {
            res.function_count++;
            res.basic_block_count++;
            in_func = true;
            continue;
        }

        if (in_func) {
            if (line == "}") {
                in_func = false;
                continue;
            }
            if (line.back() == ':') {
                res.basic_block_count++;
                continue;
            }
            res.instruction_count++;
        }
    }

    res.is_valid = res.violations.empty();
    return res;
}

IRScanResult IRScanner::scan_file(const std::string& ir_filepath) {
    std::ifstream file(ir_filepath);
    if (!file.is_open()) {
        IRScanResult res;
        res.violations.push_back("Failed to open file: " + ir_filepath);
        return res;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return scan_string(buffer.str());
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: ir_scanner <path_to_ir.ll>\n";
        return 1;
    }
    auto result = IRScanner::scan_file(argv[1]);
    std::cout << "IR Scanner Result: " << (result.is_valid ? "VALID" : "INVALID") << "\n";
    std::cout << "Functions: " << result.function_count << "\n";
    std::cout << "Instructions: " << result.instruction_count << "\n";
    std::cout << "Basic Blocks: " << result.basic_block_count << "\n";
    for (const auto& v : result.violations) {
        std::cout << "Violation: " << v << "\n";
    }
    return result.is_valid ? 0 : 2;
}

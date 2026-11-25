#include "profiler.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>

std::unordered_map<std::string, FuncMetric> CppProgramProfiler::profile(const std::string& ir_content, const std::string& src_content) {
    std::unordered_map<std::string, FuncMetric> map;
    std::istringstream stream(ir_content);
    std::string line;
    std::string current_func;
    FuncMetric metric;

    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == ';') continue;

        if (line.rfind("define ", 0) == 0) {
            std::regex re("@([a-zA-Z_][a-zA-Z0-9_]*)");
            std::smatch match;
            if (std::regex_search(line, match, re)) {
                current_func = match.str(1);
                metric = FuncMetric();
                metric.name = current_func;
                metric.is_hot = (src_content.find("[[hft::hot]]") != std::string::npos && src_content.find(current_func) != std::string::npos)
                                || (current_func.find("market") != std::string::npos) || (current_func.find("signal") != std::string::npos);
                metric.is_cold = (src_content.find("[[hft::cold]]") != std::string::npos && src_content.find(current_func) != std::string::npos)
                                 || (current_func.find("config") != std::string::npos) || (current_func.find("log") != std::string::npos);
            }
            continue;
        }

        if (!current_func.empty()) {
            if (line == "}") {
                map[current_func] = metric;
                current_func.clear();
                continue;
            }
            metric.instructions++;
            if (line.find("load ") != std::string::npos || line.find("store ") != std::string::npos || line.find("alloca ") != std::string::npos) {
                metric.memory_ops++;
            }
            if (line.find("br ") != std::string::npos || line.find("switch ") != std::string::npos) {
                metric.branches++;
            }
            if (line.find("alloca ") != std::string::npos && metric.is_hot) {
                metric.anti_patterns.push_back("LAP-001");
            }
        }
    }
    return map;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: program_profiler <ir_file.ll> [source_file.cpp]\n";
        return 1;
    }
    std::ifstream ir_file(argv[1]);
    std::stringstream ir_buf;
    ir_buf << ir_file.rdbuf();

    std::string src_buf;
    if (argc >= 3) {
        std::ifstream src_file(argv[2]);
        std::stringstream ss;
        ss << src_file.rdbuf();
        src_buf = ss.str();
    }

    auto metrics = CppProgramProfiler::profile(ir_buf.str(), src_buf);
    std::cout << "Program Profile: Analyzed " << metrics.size() << " functions\n";
    for (const auto& [name, m] : metrics) {
        std::cout << "Function: " << name
                  << " | Path: " << (m.is_hot ? "HOT" : (m.is_cold ? "COLD" : "NORMAL"))
                  << " | Instr: " << m.instructions
                  << " | MemOps: " << m.memory_ops
                  << " | Branches: " << m.branches << "\n";
    }
    return 0;
}

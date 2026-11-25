#pragma once
#include <string>
#include <vector>
#include <unordered_map>

struct FuncMetric {
    std::string name;
    bool is_hot{false};
    bool is_cold{false};
    size_t instructions{0};
    size_t memory_ops{0};
    size_t branches{0};
    size_t loops{0};
    std::vector<std::string> anti_patterns;
};

class CppProgramProfiler {
public:
    static std::unordered_map<std::string, FuncMetric> profile(const std::string& ir_content, const std::string& src_content = "");
};

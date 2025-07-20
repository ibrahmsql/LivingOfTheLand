#pragma once

#include <string>
#include <vector>

namespace SudoAnalysis {
    struct SudoRule {
        std::string user;
        std::string host;
        std::string asUser;
        std::string command;
        bool noPassword;
        bool isExploitable;
    };
    
    // Analyze sudo rules in the system
    std::vector<SudoRule> analyzeSudoRules();
    
    // Display sudo rules analysis results
    void displaySudoRules();
    
    // Check if a sudo rule is potentially exploitable
    bool isExploitableSudoRule(const std::string& command);
} 
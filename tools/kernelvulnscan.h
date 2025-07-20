#pragma once

#include <string>
#include <vector>

namespace KernelVulnScan {
    struct KernelVulnerability {
        std::string cve;
        std::string description;
        std::string severity;
        bool isVulnerable;
    };
    
    struct KernelInfo {
        std::string version;
        std::string release;
        std::string architecture;
        std::vector<KernelVulnerability> vulnerabilities;
    };
    
    // Get kernel information
    KernelInfo getKernelInfo();
    
    // Check for common kernel vulnerabilities
    std::vector<KernelVulnerability> checkCommonVulnerabilities(const KernelInfo& kernel);
    
    // Scan and display kernel vulnerabilities
    void scanKernelVulnerabilities();
} 
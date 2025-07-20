#pragma once

#include <string>
#include <vector>
#include <map>

namespace CVEAnalysis {
    struct CVEInfo {
        std::string cveID;
        std::string description;
        std::string severity;
        std::string affectedSoftware;
        std::string affectedVersions;
        std::string fixedVersions;
        std::string exploitAvailable;
        std::string remediationSteps;
        bool isVulnerable;
    };
    
    // Check for specific CVEs
    std::vector<CVEInfo> checkCVE2025_32462();
    std::vector<CVEInfo> checkCVE2025_32463();
    
    // Check for all known CVEs
    std::vector<CVEInfo> checkAllCVEs();
    
    // Display CVE information
    void displayCVEInfo(const std::vector<CVEInfo>& cveList);
    
    // Check if specific software is installed and vulnerable
    bool isSoftwareVulnerable(const std::string& software, const std::string& versionConstraint);
    
    // Get software version
    std::string getSoftwareVersion(const std::string& software);
    
    // Compare version strings
    bool isVersionLessThan(const std::string& version1, const std::string& version2);
} 
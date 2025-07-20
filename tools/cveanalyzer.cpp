#include "cveanalyzer.h"
#include "executils.h"
#include <iostream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cctype>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace CVEAnalysis {

// Helper function to trim whitespace
std::string trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), [](int c) { return std::isspace(c); });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](int c) { return std::isspace(c); }).base();
    
    return (start < end) ? std::string(start, end) : std::string();
}

// Helper function to parse version string into components
std::vector<int> parseVersion(const std::string& version) {
    std::vector<int> components;
    std::regex versionRegex("(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:\\.(\\d+))?(?:[p|P](\\d+))?");
    std::smatch matches;
    
    if (std::regex_search(version, matches, versionRegex)) {
        for (size_t i = 1; i < matches.size(); ++i) {
            if (matches[i].matched) {
                components.push_back(std::stoi(matches[i].str()));
            } else {
                components.push_back(0);
            }
        }
    }
    
    return components;
}

// Compare version strings
bool isVersionLessThan(const std::string& version1, const std::string& version2) {
    auto v1 = parseVersion(version1);
    auto v2 = parseVersion(version2);
    
    // Ensure both vectors have the same size
    while (v1.size() < v2.size()) v1.push_back(0);
    while (v2.size() < v1.size()) v2.push_back(0);
    
    return v1 < v2;
}

// Check if version is in range (inclusive of min, exclusive of max)
bool isVersionInRange(const std::string& version, const std::string& minVersion, const std::string& maxVersion) {
    return (!isVersionLessThan(version, minVersion) || version == minVersion) && 
           isVersionLessThan(version, maxVersion);
}

// Get software version
std::string getSoftwareVersion(const std::string& software) {
    // Try different commands to get version
    std::vector<std::string> versionCommands = {
        software + " --version 2>/dev/null | head -1",
        software + " -v 2>/dev/null | head -1",
        software + " -V 2>/dev/null | head -1",
        software + " version 2>/dev/null | head -1",
        "dpkg -l " + software + " 2>/dev/null | grep " + software,
        "rpm -q " + software + " 2>/dev/null",
        "pacman -Q " + software + " 2>/dev/null"
    };
    
    for (const auto& cmd : versionCommands) {
        std::string output = ExecUtils::execCommand(cmd);
        if (!output.empty()) {
            // Try to extract version number
            std::regex versionRegex("(\\d+(?:\\.\\d+)+(?:[p|P]\\d+)?)");
            std::smatch matches;
            if (std::regex_search(output, matches, versionRegex)) {
                return matches[1].str();
            }
            return output; // Return raw output if no version pattern found
        }
    }
    
    return ""; // Software not found or version not detectable
}

// Check if specific software is installed and vulnerable
bool isSoftwareVulnerable(const std::string& software, const std::string& versionConstraint) {
    // Check if software is installed
    if (ExecUtils::commandExists(software) != 1) {
        return false; // Software not installed
    }
    
    std::string version = getSoftwareVersion(software);
    if (version.empty()) {
        return false; // Can't determine version
    }
    
    // Parse version constraint
    // Format: "<2.3.4" or ">=1.2.3,<2.0.0" or "==1.2.3"
    std::vector<std::pair<std::string, std::string>> constraints;
    std::istringstream constraintStream(versionConstraint);
    std::string constraint;
    
    while (std::getline(constraintStream, constraint, ',')) {
        constraint = trim(constraint);
        if (constraint.empty()) continue;
        
        std::regex constraintRegex("([<>=]+)(.+)");
        std::smatch matches;
        if (std::regex_match(constraint, matches, constraintRegex)) {
            constraints.push_back({matches[1].str(), matches[2].str()});
        }
    }
    
    // Check each constraint
    for (const auto& [op, ver] : constraints) {
        if (op == "<" && !isVersionLessThan(version, ver)) {
            return false;
        } else if (op == "<=" && (isVersionLessThan(ver, version) && version != ver)) {
            return false;
        } else if (op == ">" && !isVersionLessThan(ver, version)) {
            return false;
        } else if (op == ">=" && isVersionLessThan(version, ver)) {
            return false;
        } else if (op == "==" && version != ver) {
            return false;
        }
    }
    
    return true; // All constraints satisfied
}

// Check for CVE-2025-32462
std::vector<CVEInfo> checkCVE2025_32462() {
    std::vector<CVEInfo> results;
    
    CVEInfo cve;
    cve.cveID = "CVE-2025-32462";
    cve.description = "Sudo Policy-Check Flaw - allows attackers to bypass host checks and execute commands as root";
    cve.severity = "High";
    cve.affectedSoftware = "sudo";
    cve.affectedVersions = ">=1.8.8,<1.9.17p1";
    cve.fixedVersions = "1.9.17p1 or later";
    cve.exploitAvailable = "Yes";
    cve.remediationSteps = "1. Update sudo to version 1.9.17p1 or later\n"
                          "2. Review host-specific rules in /etc/sudoers*\n"
                          "3. Convert host-specific rules to group-based or tag-based controls where possible";
    
    // Check if sudo is installed and vulnerable
    if (ExecUtils::commandExists("sudo") == 1) {
        std::string sudoVersion = ExecUtils::execCommand("sudo -V 2>/dev/null | head -1");
        
        // Extract version number
        std::regex versionRegex("(\\d+\\.\\d+\\.\\d+(?:[p|P]\\d+)?)");
        std::smatch matches;
        if (std::regex_search(sudoVersion, matches, versionRegex)) {
            std::string version = matches[1].str();
            
            // Check if version is in vulnerable range (1.8.8 to 1.9.17)
            if (isVersionInRange(version, "1.8.8", "1.9.17p1")) {
                cve.isVulnerable = true;
            } else {
                cve.isVulnerable = false;
            }
        } else {
            // If version can't be determined, assume vulnerable
            cve.isVulnerable = true;
        }
    } else {
        // sudo not installed
        cve.isVulnerable = false;
    }
    
    results.push_back(cve);
    
    return results;
}

// Check for CVE-2025-32463
std::vector<CVEInfo> checkCVE2025_32463() {
    std::vector<CVEInfo> results;
    
    CVEInfo cve;
    cve.cveID = "CVE-2025-32463";
    cve.description = "Sudo 'chroot to root' vulnerability - allows attackers to load malicious libraries with root privileges";
    cve.severity = "Critical (CVSS 9.3)";
    cve.affectedSoftware = "sudo";
    cve.affectedVersions = ">=1.9.14,<1.9.17p1";
    cve.fixedVersions = "1.9.17p1 or later";
    cve.exploitAvailable = "Yes";
    cve.remediationSteps = "1. Update sudo to version 1.9.17p1 or later\n"
                          "2. Disable deprecated features - Add 'Defaults !use_chroot' to sudoers\n"
                          "3. Delete any CHROOT= / runchroot=* directives\n"
                          "4. Harden world-writable areas - Remount /tmp, /var/tmp, /dev/shm with nosuid,nodev,noexec";
    
    // Check if sudo is installed and vulnerable
    if (ExecUtils::commandExists("sudo") == 1) {
        std::string sudoVersion = ExecUtils::execCommand("sudo -V 2>/dev/null | head -1");
        
        // Extract version number
        std::regex versionRegex("(\\d+\\.\\d+\\.\\d+(?:[p|P]\\d+)?)");
        std::smatch matches;
        if (std::regex_search(sudoVersion, matches, versionRegex)) {
            std::string version = matches[1].str();
            
            // Check if version is in vulnerable range (1.9.14 to 1.9.17)
            if (isVersionInRange(version, "1.9.14", "1.9.17p1")) {
                cve.isVulnerable = true;
            } else {
                cve.isVulnerable = false;
            }
        } else {
            // If version can't be determined, assume vulnerable
            cve.isVulnerable = true;
        }
        
        // Check if chroot feature is enabled
        if (!cve.isVulnerable) {
            // Even if the version is patched, check if chroot is still enabled
            std::string sudoersContent = ExecUtils::execCommand("sudo cat /etc/sudoers 2>/dev/null | grep -E 'use_chroot|CHROOT=|runchroot='");
            if (!sudoersContent.empty() && sudoersContent.find("!use_chroot") == std::string::npos) {
                // If chroot features are still enabled, mark as potentially vulnerable
                cve.isVulnerable = true;
                cve.description += " (Chroot features still enabled despite patched version)";
            }
        }
    } else {
        // sudo not installed
        cve.isVulnerable = false;
    }
    
    results.push_back(cve);
    
    return results;
}

// Check for all known CVEs
std::vector<CVEInfo> checkAllCVEs() {
    std::vector<CVEInfo> allResults;
    
    // Check for CVE-2025-32462
    auto results1 = checkCVE2025_32462();
    allResults.insert(allResults.end(), results1.begin(), results1.end());
    
    // Check for CVE-2025-32463
    auto results2 = checkCVE2025_32463();
    allResults.insert(allResults.end(), results2.begin(), results2.end());
    
    // Add checks for more CVEs here
    
    return allResults;
}

// Display CVE information
void displayCVEInfo(const std::vector<CVEInfo>& cveList) {
    std::cout << BOLD << "\n[+] CVE Vulnerability Scan Results:" << RESET << std::endl;
    
    int vulnerableCount = 0;
    
    for (const auto& cve : cveList) {
        if (cve.isVulnerable) {
            vulnerableCount++;
            std::cout << RED << "  [!] " << RESET << "Vulnerable to " << BOLD << cve.cveID << RESET 
                      << " - " << cve.description << std::endl;
            std::cout << "      Severity: " << YELLOW << cve.severity << RESET << std::endl;
            std::cout << "      Affected Software: " << CYAN << cve.affectedSoftware << RESET << std::endl;
            std::cout << "      Affected Versions: " << cve.affectedVersions << std::endl;
            std::cout << "      Fixed in: " << GREEN << cve.fixedVersions << RESET << std::endl;
            
            if (cve.exploitAvailable == "Yes") {
                std::cout << RED << "      Exploit Available: Yes" << RESET << std::endl;
            } else {
                std::cout << "      Exploit Available: " << cve.exploitAvailable << std::endl;
            }
            
            std::cout << "      Remediation Steps:" << std::endl;
            std::istringstream remediationStream(cve.remediationSteps);
            std::string step;
            while (std::getline(remediationStream, step)) {
                std::cout << CYAN << "        " << step << RESET << std::endl;
            }
            std::cout << std::endl;
        } else {
            std::cout << GREEN << "  [✓] " << RESET << "Not vulnerable to " << cve.cveID << std::endl;
        }
    }
    
    if (vulnerableCount > 0) {
        std::cout << BOLD << RED << "\n  [!] Found " << vulnerableCount << " vulnerabilities!" << RESET << std::endl;
    } else {
        std::cout << BOLD << GREEN << "\n  [✓] No vulnerabilities detected!" << RESET << std::endl;
    }
}

} // namespace CVEAnalysis 
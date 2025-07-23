#include "kernelvulnscan.h"
#include "executils.h"
#include <iostream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <map>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace KernelVulnScan {

KernelInfo getKernelInfo() {
    KernelInfo info;
    
    // Get kernel version
    std::string uname = ExecUtils::execCommand("uname -r");
    // Remove trailing newline
    if (!uname.empty() && uname.back() == '\n') {
        uname.pop_back();
    }
    info.version = uname;
    
    // Get kernel release
    std::string release = ExecUtils::execCommand("uname -v");
    // Remove trailing newline
    if (!release.empty() && release.back() == '\n') {
        release.pop_back();
    }
    info.release = release;
    
    // Get architecture
    std::string arch = ExecUtils::execCommand("uname -m");
    // Remove trailing newline
    if (!arch.empty() && arch.back() == '\n') {
        arch.pop_back();
    }
    info.architecture = arch;
    
    return info;
}

// Helper function to compare kernel versions
bool isKernelVersionLessThan(const std::string& version, int major, int minor, int patch) {
    std::regex kernelRegex("(\\d+)\\.(\\d+)\\.(\\d+)");
    std::smatch matches;
    
    if (std::regex_search(version, matches, kernelRegex) && matches.size() > 3) {
        int vMajor = std::stoi(matches[1].str());
        int vMinor = std::stoi(matches[2].str());
        int vPatch = std::stoi(matches[3].str());
        
        if (vMajor < major) return true;
        if (vMajor > major) return false;
        
        if (vMinor < minor) return true;
        if (vMinor > minor) return false;
        
        return vPatch < patch;
    }
    
    return false;
}

std::vector<KernelVulnerability> checkCommonVulnerabilities(const KernelInfo& kernel) {
    std::vector<KernelVulnerability> vulns;
    
    // Map of CVEs to check
    std::map<std::string, std::pair<std::string, std::string>> vulnDatabase = {
        {"CVE-2016-5195", {"DirtyCow - Race condition in mm/gup.c", "High"}},
        {"CVE-2017-5754", {"Meltdown - Rogue data cache load", "High"}},
        {"CVE-2017-5715", {"Spectre Variant 2 - Branch target injection", "High"}},
        {"CVE-2017-5753", {"Spectre Variant 1 - Bounds check bypass", "High"}},
        {"CVE-2018-3620", {"L1 Terminal Fault (L1TF) - Foreshadow", "High"}},
        {"CVE-2019-11815", {"Race condition in rds_tcp_kill_sock", "Medium"}},
        {"CVE-2019-15666", {"CLONE_NEWUSER|CLONE_FS privilege escalation", "High"}},
        {"CVE-2021-3156", {"Sudo Baron Samedit", "Critical"}},
        {"CVE-2021-33909", {"Sequoia - size_t-to-int conversion vulnerability", "High"}},
        {"CVE-2022-0847", {"Dirty Pipe - Overwriting data in read-only files", "Critical"}},
        {"CVE-2022-2588", {"nft_object Use-After-Free vulnerability", "High"}}
    };
    
    // Check for DirtyCow (CVE-2016-5195)
    KernelVulnerability dirtyCow;
    dirtyCow.cve = "CVE-2016-5195";
    dirtyCow.description = vulnDatabase[dirtyCow.cve].first;
    dirtyCow.severity = vulnDatabase[dirtyCow.cve].second;
    dirtyCow.isVulnerable = isKernelVersionLessThan(kernel.version, 4, 8, 3);
    vulns.push_back(dirtyCow);
    
    // Check for Meltdown (CVE-2017-5754)
    KernelVulnerability meltdown;
    meltdown.cve = "CVE-2017-5754";
    meltdown.description = vulnDatabase[meltdown.cve].first;
    meltdown.severity = vulnDatabase[meltdown.cve].second;
    
    // Check if CPU is vulnerable
    std::string cpuInfo = ExecUtils::execCommand("cat /proc/cpuinfo");
    
    // Check if kernel has patches
    std::string cmdline = ExecUtils::execCommand("cat /proc/cmdline");
    
    if (cpuInfo.find("GenuineIntel") != std::string::npos && 
        (cmdline.find("pti=off") != std::string::npos || 
         cmdline.find("nopti") != std::string::npos)) {
        meltdown.isVulnerable = true;
    } else if (isKernelVersionLessThan(kernel.version, 4, 14, 11)) {
        // Kernel versions before 4.14.11 are vulnerable if not patched
        meltdown.isVulnerable = true;
    } else {
        meltdown.isVulnerable = false;
    }
    
    vulns.push_back(meltdown);
    
    // Check for Spectre Variant 1 (CVE-2017-5753)
    KernelVulnerability spectre1;
    spectre1.cve = "CVE-2017-5753";
    spectre1.description = vulnDatabase[spectre1.cve].first;
    spectre1.severity = vulnDatabase[spectre1.cve].second;
    
    if (isKernelVersionLessThan(kernel.version, 4, 14, 18)) {
        spectre1.isVulnerable = true;
    } else {
        spectre1.isVulnerable = false;
    }
    
    vulns.push_back(spectre1);
    
    // Check for Spectre Variant 2 (CVE-2017-5715)
    KernelVulnerability spectre2;
    spectre2.cve = "CVE-2017-5715";
    spectre2.description = vulnDatabase[spectre2.cve].first;
    spectre2.severity = vulnDatabase[spectre2.cve].second;
    
    if (isKernelVersionLessThan(kernel.version, 4, 14, 18)) {
        spectre2.isVulnerable = true;
    } else {
        spectre2.isVulnerable = false;
    }
    
    vulns.push_back(spectre2);
    
    // Check for Dirty Pipe (CVE-2022-0847)
    KernelVulnerability dirtyPipe;
    dirtyPipe.cve = "CVE-2022-0847";
    dirtyPipe.description = vulnDatabase[dirtyPipe.cve].first;
    dirtyPipe.severity = vulnDatabase[dirtyPipe.cve].second;
    
    // Vulnerable in kernels >= 5.8 and < 5.16.11 / 5.15.25 / 5.10.102
    std::regex kernelRegex("(\\d+)\\.(\\d+)\\.(\\d+)");
    std::smatch matches;
    
    if (std::regex_search(kernel.version, matches, kernelRegex) && matches.size() > 3) {
        int major = std::stoi(matches[1].str());
        int minor = std::stoi(matches[2].str());
        int patch = std::stoi(matches[3].str());
        
        if (major == 5) {
            if ((minor == 8 || minor == 9 || minor == 11 || minor == 12 || minor == 13 || minor == 14) ||
                (minor == 15 && patch < 25) ||
                (minor == 16 && patch < 11) ||
                (minor == 10 && patch < 102)) {
                dirtyPipe.isVulnerable = true;
            } else {
                dirtyPipe.isVulnerable = false;
            }
        } else {
            dirtyPipe.isVulnerable = false;
        }
    } else {
        dirtyPipe.isVulnerable = false;
    }
    
    vulns.push_back(dirtyPipe);
    
    return vulns;
}

void scanKernelVulnerabilities() {
    std::cout << BOLD << "\n[+] Scanning for Kernel Vulnerabilities..." << RESET << std::endl;
    
    KernelInfo kernel = getKernelInfo();
    
    std::cout << BLUE << "  [*] " << RESET << "Kernel Version: " << CYAN << kernel.version << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Kernel Release: " << CYAN << kernel.release << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Architecture: " << CYAN << kernel.architecture << RESET << std::endl;
    
    std::vector<KernelVulnerability> vulnerabilities = checkCommonVulnerabilities(kernel);
    
    std::cout << BOLD << "\n  [*] Vulnerability Scan Results:" << RESET << std::endl;
    
    int vulnerableCount = 0;
    for (const auto& vuln : vulnerabilities) {
        if (vuln.isVulnerable) {
            vulnerableCount++;
            std::cout << RED << "    [!] " << RESET << vuln.cve << " - " << vuln.description 
                      << " (Severity: " << YELLOW << vuln.severity << RESET << ")" << std::endl;
        } else {
            std::cout << GREEN << "    [✓] " << RESET << "Not vulnerable to " << vuln.cve << std::endl;
        }
    }
    
    if (vulnerableCount > 0) {
        std::cout << BOLD << RED << "\n  [!] Found " << vulnerableCount << " potential vulnerabilities!" << RESET << std::endl;
    } else {
        std::cout << BOLD << GREEN << "\n  [✓] No kernel vulnerabilities detected!" << RESET << std::endl;
    }
}

} // namespace KernelVulnScan
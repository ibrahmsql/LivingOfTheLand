#include "dockeranalyzer.h"
#include "executils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <unistd.h>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace DockerAnalysis {

// Helper function to trim whitespace
std::string trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), [](int c) { return std::isspace(c); });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](int c) { return std::isspace(c); }).base();
    
    return (start < end) ? std::string(start, end) : std::string();
}

// Helper function to execute a command and return its output
std::string execCommand(const std::string& cmd) {
    return ExecUtils::execCommand(cmd);
}

// Docker detection and information gathering
DockerInfo getDockerInfo() {
    DockerInfo info;
    
    // Check if Docker is installed
    std::string dockerVersion = execCommand("docker --version 2>/dev/null");
    info.isDockerInstalled = !dockerVersion.empty();
    info.dockerVersion = dockerVersion;
    
    // Check if running in a Docker container
    info.isRunningInContainer = isRunningInDocker();
    
    if (info.isRunningInContainer) {
        // Get container ID
        info.containerId = getContainerId();
        
        // Get container name
        info.containerName = getContainerName();
        
        // Get container image
        info.containerImage = getContainerImage();
        
        // Get container mounts
        info.mounts = getContainerMounts();
        
        // Get container capabilities
        info.capabilities = getContainerCapabilities();
        
        // Check if container is privileged
        info.privileged = isPrivilegedContainer();
        
        // Get container runtime
        std::string cgroupInfo = execCommand("cat /proc/self/cgroup 2>/dev/null");
        if (cgroupInfo.find("docker") != std::string::npos) {
            info.containerRuntime = "Docker";
        } else if (cgroupInfo.find("containerd") != std::string::npos) {
            info.containerRuntime = "containerd";
        } else if (cgroupInfo.find("crio") != std::string::npos) {
            info.containerRuntime = "CRI-O";
        } else {
            info.containerRuntime = "Unknown";
        }
        
        // Get security options
        std::string securityOpts = execCommand("cat /proc/self/status | grep CapEff 2>/dev/null");
        if (!securityOpts.empty()) {
            info.securityOpts.push_back(securityOpts);
        }
        
        std::string apparmorStatus = execCommand("cat /proc/self/attr/current 2>/dev/null");
        if (!apparmorStatus.empty()) {
            info.securityOpts.push_back("AppArmor: " + apparmorStatus);
        }
        
        std::string seccompStatus = execCommand("grep Seccomp /proc/self/status 2>/dev/null");
        if (!seccompStatus.empty()) {
            info.securityOpts.push_back(seccompStatus);
        }
    }
    
    return info;
}

bool isRunningInDocker() {
    // Method 1: Check for .dockerenv file
    if (std::filesystem::exists("/.dockerenv")) {
        return true;
    }
    
    // Method 2: Check cgroup
    std::string cgroupContent = execCommand("cat /proc/1/cgroup 2>/dev/null");
    if (cgroupContent.find("docker") != std::string::npos || 
        cgroupContent.find("containerd") != std::string::npos ||
        cgroupContent.find("kubepods") != std::string::npos) {
        return true;
    }
    
    // Method 3: Check hostname
    std::string hostname = execCommand("hostname 2>/dev/null");
    if (hostname.length() == 12 && std::all_of(hostname.begin(), hostname.end(), [](char c) {
        return std::isxdigit(c);
    })) {
        return true;
    }
    
    return false;
}

std::string getContainerId() {
    // Method 1: From cgroup
    std::string cgroupContent = execCommand("cat /proc/self/cgroup 2>/dev/null");
    std::regex containerIdRegex("/docker/([a-f0-9]{64})");
    std::smatch match;
    
    if (std::regex_search(cgroupContent, match, containerIdRegex)) {
        return match[1].str();
    }
    
    // Method 2: From hostname
    std::string hostname = execCommand("hostname 2>/dev/null");
    if (hostname.length() == 12 && std::all_of(hostname.begin(), hostname.end(), [](char c) {
        return std::isxdigit(c);
    })) {
        return hostname;
    }
    
    return "unknown";
}

std::string getContainerName() {
    // Note: This is difficult to determine from inside the container
    // without access to the Docker socket
    return "unknown";
}

std::string getContainerImage() {
    // Try to get from environment variables
    std::string image = execCommand("env | grep 'IMAGE=' 2>/dev/null");
    if (!image.empty()) {
        size_t pos = image.find('=');
        if (pos != std::string::npos) {
            return image.substr(pos + 1);
        }
    }
    
    return "unknown";
}

std::vector<std::string> getContainerMounts() {
    std::vector<std::string> mounts;
    
    std::string mountInfo = execCommand("cat /proc/mounts 2>/dev/null");
    std::istringstream mountStream(mountInfo);
    std::string line;
    
    while (std::getline(mountStream, line)) {
        mounts.push_back(line);
    }
    
    return mounts;
}

std::vector<std::string> getContainerCapabilities() {
    std::vector<std::string> capabilities;
    
    std::string capsInfo = execCommand("cat /proc/self/status | grep Cap 2>/dev/null");
    std::istringstream capsStream(capsInfo);
    std::string line;
    
    while (std::getline(capsStream, line)) {
        capabilities.push_back(line);
    }
    
    return capabilities;
}

bool isPrivilegedContainer() {
    // Check for SYS_ADMIN capability
    std::string capsInfo = execCommand("cat /proc/self/status | grep CapEff 2>/dev/null");
    
    // Convert hex capability mask to binary and check for SYS_ADMIN (bit 21)
    if (!capsInfo.empty()) {
        size_t pos = capsInfo.find(':');
        if (pos != std::string::npos) {
            std::string capHex = trim(capsInfo.substr(pos + 1));
            
            // Convert hex to decimal
            unsigned long long capValue = std::stoull(capHex, nullptr, 16);
            
            // Check if SYS_ADMIN bit (21) is set
            return (capValue & (1ULL << 21)) != 0;
        }
    }
    
    return false;
}

// Docker security checks
std::vector<DockerVulnerability> checkDockerVulnerabilities(const DockerInfo& info) {
    std::vector<DockerVulnerability> vulns;
    
    // Check for Docker socket
    if (checkForDockerSocket()) {
        DockerVulnerability vuln;
        vuln.id = "DOCKER-1";
        vuln.description = "Docker socket is accessible from inside the container";
        vuln.severity = "Critical";
        vuln.isVulnerable = true;
        vuln.remediation = "Remove the Docker socket mount from the container";
        vulns.push_back(vuln);
    }
    
    // Check for host mount
    if (checkForHostMount()) {
        DockerVulnerability vuln;
        vuln.id = "DOCKER-2";
        vuln.description = "Host filesystem is mounted inside the container";
        vuln.severity = "Critical";
        vuln.isVulnerable = true;
        vuln.remediation = "Remove host filesystem mounts from the container";
        vulns.push_back(vuln);
    }
    
    // Check for privileged mode
    if (info.privileged) {
        DockerVulnerability vuln;
        vuln.id = "DOCKER-3";
        vuln.description = "Container is running in privileged mode";
        vuln.severity = "Critical";
        vuln.isVulnerable = true;
        vuln.remediation = "Do not run containers with --privileged flag";
        vulns.push_back(vuln);
    }
    
    // Check for user namespace
    if (!checkForUserNamespace()) {
        DockerVulnerability vuln;
        vuln.id = "DOCKER-4";
        vuln.description = "User namespace is not enabled";
        vuln.severity = "Medium";
        vuln.isVulnerable = true;
        vuln.remediation = "Enable user namespace with --userns-remap";
        vulns.push_back(vuln);
    }
    
    // Check for AppArmor
    if (!checkForAppArmor()) {
        DockerVulnerability vuln;
        vuln.id = "DOCKER-5";
        vuln.description = "AppArmor is not enabled";
        vuln.severity = "Medium";
        vuln.isVulnerable = true;
        vuln.remediation = "Enable AppArmor with --security-opt apparmor=docker-default";
        vulns.push_back(vuln);
    }
    
    // Check for Seccomp
    if (!checkForSeccomp()) {
        DockerVulnerability vuln;
        vuln.id = "DOCKER-6";
        vuln.description = "Seccomp is not enabled";
        vuln.severity = "Medium";
        vuln.isVulnerable = true;
        vuln.remediation = "Enable Seccomp with --security-opt seccomp=default.json";
        vulns.push_back(vuln);
    }
    
    return vulns;
}

bool checkForDockerSocket() {
    return std::filesystem::exists("/var/run/docker.sock") || 
           std::filesystem::exists("/run/docker.sock");
}

bool checkForDockerSocketMount() {
    std::string mountInfo = execCommand("cat /proc/mounts 2>/dev/null");
    return mountInfo.find("docker.sock") != std::string::npos;
}

bool checkForHostMount() {
    std::string mountInfo = execCommand("cat /proc/mounts 2>/dev/null");
    return mountInfo.find("/host") != std::string::npos || 
           mountInfo.find("/hostfs") != std::string::npos;
}

bool checkForPrivilegedMode() {
    return isPrivilegedContainer();
}

bool checkForCapabilities() {
    std::string capsInfo = execCommand("cat /proc/self/status | grep CapEff 2>/dev/null");
    
    // Convert hex capability mask to binary and check for dangerous capabilities
    if (!capsInfo.empty()) {
        size_t pos = capsInfo.find(':');
        if (pos != std::string::npos) {
            std::string capHex = trim(capsInfo.substr(pos + 1));
            
            // Convert hex to decimal
            unsigned long long capValue = std::stoull(capHex, nullptr, 16);
            
            // Check for dangerous capabilities
            return (capValue & (1ULL << 21)) != 0 || // SYS_ADMIN
                   (capValue & (1ULL << 16)) != 0 || // SYS_RAWIO
                   (capValue & (1ULL << 17)) != 0 || // SYS_CHROOT
                   (capValue & (1ULL << 18)) != 0;   // SYS_PTRACE
        }
    }
    
    return false;
}

bool checkForUserNamespace() {
    std::string usernsInfo = execCommand("cat /proc/self/uid_map 2>/dev/null");
    
    // If user namespace is enabled, uid_map will not show 0 0 4294967295
    return usernsInfo != "         0          0 4294967295\n";
}

bool checkForAppArmor() {
    std::string apparmorStatus = execCommand("cat /proc/self/attr/current 2>/dev/null");
    return apparmorStatus.find("docker-default") != std::string::npos;
}

bool checkForSeccomp() {
    std::string seccompStatus = execCommand("grep Seccomp /proc/self/status 2>/dev/null");
    
    // Seccomp mode 2 means filter is enabled
    return seccompStatus.find("2") != std::string::npos;
}

// Docker escape vectors
std::vector<std::string> findDockerEscapeVectors(const DockerInfo& info) {
    std::vector<std::string> escapeVectors;
    
    // Check for Docker socket
    if (checkForDockerSocket()) {
        escapeVectors.push_back("Docker socket is accessible: can create privileged containers");
    }
    
    // Check for host mount
    if (checkForHostMount()) {
        escapeVectors.push_back("Host filesystem is mounted: can access host files");
    }
    
    // Check for privileged mode
    if (info.privileged) {
        escapeVectors.push_back("Container is privileged: can access host devices and mount filesystems");
    }
    
    // Check for dangerous capabilities
    if (checkForCapabilities()) {
        escapeVectors.push_back("Container has dangerous capabilities: can perform privileged operations");
    }
    
    // Check for writable /proc
    if (std::filesystem::exists("/proc/sys/kernel/core_pattern") && 
        access("/proc/sys/kernel/core_pattern", W_OK) == 0) {
        escapeVectors.push_back("Writable /proc: can modify kernel parameters");
    }
    
    // Check for device access
    if (std::filesystem::exists("/dev/kmsg") && 
        access("/dev/kmsg", R_OK | W_OK) == 0) {
        escapeVectors.push_back("Access to /dev/kmsg: can read/write kernel messages");
    }
    
    return escapeVectors;
}

// Display functions
void displayDockerInfo(const DockerInfo& info) {
    std::cout << BOLD << BLUE << "[+] Docker Information:" << RESET << std::endl;
    
    if (info.isDockerInstalled) {
        std::cout << BLUE << "  [*] " << RESET << "Docker Version: " << CYAN << info.dockerVersion << RESET << std::endl;
    }
    
    if (info.isRunningInContainer) {
        std::cout << YELLOW << "  [!] " << RESET << "Running inside a container" << std::endl;
        std::cout << BLUE << "  [*] " << RESET << "Container ID: " << CYAN << info.containerId << RESET << std::endl;
        
        if (info.containerName != "unknown") {
            std::cout << BLUE << "  [*] " << RESET << "Container Name: " << CYAN << info.containerName << RESET << std::endl;
        }
        
        if (info.containerImage != "unknown") {
            std::cout << BLUE << "  [*] " << RESET << "Container Image: " << CYAN << info.containerImage << RESET << std::endl;
        }
        
        std::cout << BLUE << "  [*] " << RESET << "Container Runtime: " << CYAN << info.containerRuntime << RESET << std::endl;
        
        if (info.privileged) {
            std::cout << RED << "  [!] " << RESET << "Container is running in privileged mode!" << std::endl;
        }
        
        // Display security options
        if (!info.securityOpts.empty()) {
            std::cout << BLUE << "  [*] " << RESET << "Security Options:" << std::endl;
            for (const auto& opt : info.securityOpts) {
                std::cout << "    " << opt << std::endl;
            }
        }
        
        // Display mounts
        if (!info.mounts.empty()) {
            std::cout << BLUE << "  [*] " << RESET << "Container Mounts:" << std::endl;
            for (const auto& mount : info.mounts) {
                if (mount.find("docker.sock") != std::string::npos) {
                    std::cout << RED << "    " << mount << " (Docker socket mounted!)" << RESET << std::endl;
                } else if (mount.find("/host") != std::string::npos || mount.find("/hostfs") != std::string::npos) {
                    std::cout << RED << "    " << mount << " (Host filesystem mounted!)" << RESET << std::endl;
                } else {
                    std::cout << "    " << mount << std::endl;
                }
            }
        }
    } else {
        std::cout << GREEN << "  [✓] " << RESET << "Not running inside a container" << std::endl;
    }
}

void displayDockerVulnerabilities(const std::vector<DockerVulnerability>& vulns) {
    if (vulns.empty()) {
        std::cout << GREEN << "  [✓] " << RESET << "No Docker vulnerabilities found" << std::endl;
        return;
    }
    
    std::cout << BOLD << RED << "[!] Docker Vulnerabilities:" << RESET << std::endl;
    
    for (const auto& vuln : vulns) {
        std::cout << RED << "  [!] " << RESET << vuln.id << ": " << vuln.description << std::endl;
        std::cout << "      Severity: " << (vuln.severity == "Critical" ? RED : YELLOW) << vuln.severity << RESET << std::endl;
        std::cout << "      Remediation: " << CYAN << vuln.remediation << RESET << std::endl;
        std::cout << std::endl;
    }
}

void performDockerAnalysis() {
    std::cout << BOLD << BLUE << "\n===== Docker Analysis =====" << RESET << std::endl;
    
    DockerInfo info = getDockerInfo();
    displayDockerInfo(info);
    
    if (info.isRunningInContainer) {
        std::vector<DockerVulnerability> vulns = checkDockerVulnerabilities(info);
        displayDockerVulnerabilities(vulns);
        
        std::vector<std::string> escapeVectors = findDockerEscapeVectors(info);
        if (!escapeVectors.empty()) {
            std::cout << BOLD << RED << "[!] Potential Container Escape Vectors:" << RESET << std::endl;
            for (const auto& vector : escapeVectors) {
                std::cout << RED << "  [!] " << RESET << vector << std::endl;
            }
        }
    }
}

} // namespace DockerAnalysis 
#include "containeranalyzer.h"
#include "executils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <unistd.h> // W_OK tanımı için eklendi

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace ContainerAnalysis {

std::string containerTypeToString(ContainerType type) {
    switch (type) {
        case ContainerType::NONE: return "None";
        case ContainerType::DOCKER: return "Docker";
        case ContainerType::LXC: return "LXC";
        case ContainerType::KUBERNETES: return "Kubernetes";
        case ContainerType::AWS_LAMBDA: return "AWS Lambda";
        case ContainerType::AZURE_FUNCTIONS: return "Azure Functions";
        case ContainerType::UNKNOWN: return "Unknown Container";
        default: return "Unknown";
    }
}

bool checkFileContains(const std::string& filePath, const std::string& searchStr) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.find(searchStr) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

ContainerInfo detectContainerEnvironment() {
    ContainerInfo info;
    info.type = ContainerType::NONE;
    info.privileged = false;
    info.hostNetwork = false;
    
    // Check for Docker
    bool isDocker = std::filesystem::exists("/.dockerenv") || 
                   !ExecUtils::execCommand("grep -q docker /proc/self/cgroup 2>/dev/null").empty() ||
                   !ExecUtils::execCommand("grep -q docker /proc/1/cgroup 2>/dev/null").empty();
    
    if (isDocker) {
        info.type = ContainerType::DOCKER;
        
        // Get container ID
        info.id = ExecUtils::execCommand("basename $(cat /proc/1/cpuset 2>/dev/null) 2>/dev/null");
        if (info.id.empty()) {
            info.id = ExecUtils::execCommand("cat /proc/self/cgroup | grep -o -e \"docker/.*\" | head -n 1 | sed \"s/docker\\///g\" 2>/dev/null");
        }
        info.id.erase(std::remove(info.id.begin(), info.id.end(), '\n'), info.id.end());
        
        // Get container name (requires access to Docker socket)
        info.name = ExecUtils::execCommand("docker inspect --format '{{.Name}}' $(hostname) 2>/dev/null");
        info.name.erase(std::remove(info.name.begin(), info.name.end(), '\n'), info.name.end());
        if (info.name.empty()) {
            info.name = ExecUtils::execCommand("hostname");
            info.name.erase(std::remove(info.name.begin(), info.name.end(), '\n'), info.name.end());
        }
        
        // Get image name
        info.image = ExecUtils::execCommand("docker inspect --format '{{.Config.Image}}' $(hostname) 2>/dev/null");
        info.image.erase(std::remove(info.image.begin(), info.image.end(), '\n'), info.image.end());
        
        // Check if privileged
        std::string privileged = ExecUtils::execCommand("docker inspect --format '{{.HostConfig.Privileged}}' $(hostname) 2>/dev/null");
        privileged.erase(std::remove(privileged.begin(), privileged.end(), '\n'), privileged.end());
        info.privileged = (privileged == "true");
        
        // Check if using host network
        std::string hostNetwork = ExecUtils::execCommand("docker inspect --format '{{.HostConfig.NetworkMode}}' $(hostname) 2>/dev/null");
        hostNetwork.erase(std::remove(hostNetwork.begin(), hostNetwork.end(), '\n'), hostNetwork.end());
        info.hostNetwork = (hostNetwork == "host");
        
        // Get mounts
        std::string mountsOutput = ExecUtils::execCommand("docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' $(hostname) 2>/dev/null");
        std::istringstream mountStream(mountsOutput);
        std::string mount;
        
        while (mountStream >> mount) {
            info.mounts.push_back(mount);
        }
        
        // Get capabilities
        std::string capsOutput = ExecUtils::execCommand("docker inspect --format '{{range .HostConfig.CapAdd}}{{.}} {{end}}' $(hostname) 2>/dev/null");
        std::istringstream capsStream(capsOutput);
        std::string cap;
        
        while (capsStream >> cap) {
            info.capabilities.push_back(cap);
        }
        
        // If we can't get capabilities from docker inspect, try to get them from /proc/self/status
        if (info.capabilities.empty()) {
            std::string capsFromProc = ExecUtils::execCommand("grep CapEff /proc/self/status | awk '{print $2}'");
            if (!capsFromProc.empty()) {
                info.capabilities.push_back("CapEff: " + capsFromProc);
            }
        }
    }
    // Check for LXC
    else if (std::filesystem::exists("/dev/lxd/sock") || 
            !ExecUtils::execCommand("grep -q lxc /proc/1/cgroup 2>/dev/null").empty() ||
            checkFileContains("/proc/1/environ", "container=lxc")) {
        
        info.type = ContainerType::LXC;
        
        // Get container name
        info.name = ExecUtils::execCommand("hostname");
        info.name.erase(std::remove(info.name.begin(), info.name.end(), '\n'), info.name.end());
        
        // Check for privileged mode
        std::string lxcInfo = ExecUtils::execCommand("lxc config show $(hostname) 2>/dev/null");
        if (lxcInfo.find("security.privileged: true") != std::string::npos) {
            info.privileged = true;
        }
        
        // Get mounts
        std::string mountsOutput = ExecUtils::execCommand("cat /proc/mounts | grep -i lxc");
        std::istringstream mountStream(mountsOutput);
        std::string line;
        
        while (std::getline(mountStream, line)) {
            size_t spacePos = line.find(' ');
            if (spacePos != std::string::npos) {
                size_t nextSpacePos = line.find(' ', spacePos + 1);
                if (nextSpacePos != std::string::npos) {
                    std::string source = line.substr(0, spacePos);
                    std::string dest = line.substr(spacePos + 1, nextSpacePos - spacePos - 1);
                    info.mounts.push_back(source + ":" + dest);
                }
            }
        }
    }
    // Check for Kubernetes
    else if (std::filesystem::exists("/var/run/secrets/kubernetes.io") || 
            !ExecUtils::execCommand("env | grep KUBERNETES").empty()) {
        
        info.type = ContainerType::KUBERNETES;
        
        // Get pod name
        info.name = ExecUtils::execCommand("hostname");
        info.name.erase(std::remove(info.name.begin(), info.name.end(), '\n'), info.name.end());
        
        // Get namespace from service account
        if (std::filesystem::exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace")) {
            std::string ns = ExecUtils::execCommand("cat /var/run/secrets/kubernetes.io/serviceaccount/namespace");
            ns.erase(std::remove(ns.begin(), ns.end(), '\n'), ns.end());
            info.id = "namespace: " + ns;
        }
        
        // Get container image
        std::string containerStatus = ExecUtils::execCommand("cat /proc/self/cgroup");
        if (!containerStatus.empty()) {
            info.image = "Container in Kubernetes Pod: " + info.name;
        }
        
        // Check for hostNetwork
        std::string netInfo = ExecUtils::execCommand("ip addr show | grep -i 'host'");
        if (!netInfo.empty()) {
            info.hostNetwork = true;
        }
        
        // Get mounts
        std::string mountsOutput = ExecUtils::execCommand("cat /proc/mounts | grep -i 'kubernetes'");
        std::istringstream mountStream(mountsOutput);
        std::string line;
        
        while (std::getline(mountStream, line)) {
            size_t spacePos = line.find(' ');
            if (spacePos != std::string::npos) {
                size_t nextSpacePos = line.find(' ', spacePos + 1);
                if (nextSpacePos != std::string::npos) {
                    std::string source = line.substr(0, spacePos);
                    std::string dest = line.substr(spacePos + 1, nextSpacePos - spacePos - 1);
                    info.mounts.push_back(source + ":" + dest);
                }
            }
        }
    }
    // Check for AWS Lambda
    else if (!ExecUtils::execCommand("env | grep AWS_LAMBDA").empty()) {
        info.type = ContainerType::AWS_LAMBDA;
        
        // Get function name
        std::string functionName = ExecUtils::execCommand("echo $AWS_LAMBDA_FUNCTION_NAME");
        functionName.erase(std::remove(functionName.begin(), functionName.end(), '\n'), functionName.end());
        info.name = functionName;
        
        // Get function version
        std::string functionVersion = ExecUtils::execCommand("echo $AWS_LAMBDA_FUNCTION_VERSION");
        functionVersion.erase(std::remove(functionVersion.begin(), functionVersion.end(), '\n'), functionVersion.end());
        info.id = "version: " + functionVersion;
    }
    // Check for Azure Functions
    else if (!ExecUtils::execCommand("env | grep FUNCTIONS_WORKER_RUNTIME").empty()) {
        info.type = ContainerType::AZURE_FUNCTIONS;
        
        // Get function app name
        std::string appName = ExecUtils::execCommand("echo $WEBSITE_SITE_NAME");
        appName.erase(std::remove(appName.begin(), appName.end(), '\n'), appName.end());
        info.name = appName;
    }
    // Check for generic container indicators
    else if (checkFileContains("/proc/1/environ", "container=systemd-nspawn")) {
        info.type = ContainerType::UNKNOWN;
    }
    
    return info;
}

void analyzeContainerEscapeVectors(const ContainerInfo& container) {
    if (container.type == ContainerType::NONE) {
        std::cout << GREEN << "  [✓] Not running in a container environment" << RESET << std::endl;
        return;
    }
    
    std::cout << BOLD << "\n  [*] Analyzing container escape vectors..." << RESET << std::endl;
    
    // Check privileged mode
    if (container.privileged) {
        std::cout << RED << "    [!] Container is running in privileged mode - ESCAPE POSSIBLE!" << RESET << std::endl;
        std::cout << YELLOW << "        Try: mount -t proc none /tmp/proc && chroot /host bash" << RESET << std::endl;
    }
    
    // Check for dangerous mounts
    bool hostMountFound = false;
    for (const auto& mount : container.mounts) {
        if (mount.find("/:/") != std::string::npos ||
            mount.find("/proc:/proc") != std::string::npos ||
            mount.find("/sys:/sys") != std::string::npos ||
            mount.find("/dev:/dev") != std::string::npos ||
            mount.find("/var/run/docker.sock") != std::string::npos) {
            
            std::cout << RED << "    [!] Dangerous mount found: " << mount << " - ESCAPE POSSIBLE!" << RESET << std::endl;
            hostMountFound = true;
        }
    }
    
    // Check for dangerous capabilities
    for (const auto& cap : container.capabilities) {
        if (cap == "CAP_SYS_ADMIN" || cap == "CAP_SYS_PTRACE" || 
            cap == "CAP_SYS_MODULE" || cap == "CAP_SYS_RAWIO" ||
            cap == "CAP_SYS_TIME" || cap == "CAP_SYSLOG" ||
            cap == "CAP_NET_ADMIN" || cap == "CAP_ALL") {
            
            std::cout << RED << "    [!] Dangerous capability found: " << cap << " - ESCAPE POSSIBLE!" << RESET << std::endl;
        }
    }
    
    // Check for Docker socket
    if (std::filesystem::exists("/var/run/docker.sock")) {
        std::cout << RED << "    [!] Docker socket is accessible: /var/run/docker.sock - ESCAPE POSSIBLE!" << RESET << std::endl;
        std::cout << YELLOW << "        Try: docker run -v /:/host -it ubuntu chroot /host bash" << RESET << std::endl;
    }
    
    // Check for host network
    if (container.hostNetwork) {
        std::cout << RED << "    [!] Container is using host network - Potential for network-based attacks!" << RESET << std::endl;
    }
    
    // Check for cgroup release_agent escape
    if (std::filesystem::exists("/sys/fs/cgroup/release_agent")) {
        std::cout << RED << "    [!] Cgroup release_agent is accessible - ESCAPE POSSIBLE!" << RESET << std::endl;
        std::cout << YELLOW << "        Try: echo '#!/bin/sh\\nps > /tmp/output' > /tmp/escape.sh" << RESET << std::endl;
        std::cout << YELLOW << "             chmod +x /tmp/escape.sh" << RESET << std::endl;
        std::cout << YELLOW << "             echo /tmp/escape.sh > /sys/fs/cgroup/release_agent" << RESET << std::endl;
    }
    
    // Check for writable /etc/passwd
    if (std::filesystem::exists("/etc/passwd") && 
        access("/etc/passwd", W_OK) == 0) {
        std::cout << RED << "    [!] /etc/passwd is writable - PRIVILEGE ESCALATION POSSIBLE!" << RESET << std::endl;
        std::cout << YELLOW << "        Try: echo 'root2:x:0:0:root:/root:/bin/bash' >> /etc/passwd" << RESET << std::endl;
    }
    
    // Check for writable shadow file
    if (std::filesystem::exists("/etc/shadow") && 
        access("/etc/shadow", W_OK) == 0) {
        std::cout << RED << "    [!] /etc/shadow is writable - PRIVILEGE ESCALATION POSSIBLE!" << RESET << std::endl;
    }
    
    // Check if we can create devices
    std::string mknodTest = ExecUtils::execCommand("mknod /tmp/test-device c 1 3 2>&1");
    if (mknodTest.find("Operation not permitted") == std::string::npos) {
        std::cout << RED << "    [!] Can create device files - ESCAPE POSSIBLE!" << RESET << std::endl;
        // Clean up
        ExecUtils::execCommand("rm -f /tmp/test-device 2>/dev/null");
    }
    
    // Check if we can load kernel modules
    if (std::filesystem::exists("/lib/modules") && 
        !ExecUtils::execCommand("ls -la /lib/modules 2>/dev/null").empty()) {
        std::cout << RED << "    [!] Kernel modules directory is accessible - POTENTIAL ESCAPE VECTOR!" << RESET << std::endl;
    }
    
    // Check for any writable paths in $PATH
    std::string pathEnv = ExecUtils::execCommand("echo $PATH");
    std::istringstream pathStream(pathEnv);
    std::string pathEntry;
    
    while (std::getline(pathStream, pathEntry, ':')) {
        if (access(pathEntry.c_str(), W_OK) == 0) {
            std::cout << RED << "    [!] Writable directory in PATH: " << pathEntry << " - PRIVILEGE ESCALATION VECTOR!" << RESET << std::endl;
        }
    }
    
    // Summary
    if (!container.privileged && !hostMountFound && 
        !std::filesystem::exists("/var/run/docker.sock") && 
        !container.hostNetwork && 
        !std::filesystem::exists("/sys/fs/cgroup/release_agent")) {
        std::cout << GREEN << "    [✓] No obvious container escape vectors found" << RESET << std::endl;
    }
}

} // namespace ContainerAnalysis 
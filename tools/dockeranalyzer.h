#pragma once

#include <string>
#include <vector>
#include <map>

namespace DockerAnalysis {
    struct DockerInfo {
        bool isDockerInstalled;
        bool isRunningInContainer;
        std::string dockerVersion;
        std::string containerId;
        std::string containerName;
        std::string containerImage;
        std::string containerRuntime;
        std::vector<std::string> mounts;
        std::vector<std::string> capabilities;
        std::vector<std::string> securityOpts;
        bool privileged;
    };
    
    struct DockerVulnerability {
        std::string id;
        std::string description;
        std::string severity;
        bool isVulnerable;
        std::string remediation;
    };
    
    // Docker detection and information gathering
    DockerInfo getDockerInfo();
    bool isRunningInDocker();
    std::string getContainerId();
    std::string getContainerName();
    std::string getContainerImage();
    std::vector<std::string> getContainerMounts();
    std::vector<std::string> getContainerCapabilities();
    bool isPrivilegedContainer();
    
    // Docker security checks
    std::vector<DockerVulnerability> checkDockerVulnerabilities(const DockerInfo& info);
    bool checkForDockerSocket();
    bool checkForDockerSocketMount();
    bool checkForHostMount();
    bool checkForPrivilegedMode();
    bool checkForCapabilities();
    bool checkForUserNamespace();
    bool checkForAppArmor();
    bool checkForSeccomp();
    
    // Docker escape vectors
    std::vector<std::string> findDockerEscapeVectors(const DockerInfo& info);
    
    // Display functions
    void displayDockerInfo(const DockerInfo& info);
    void displayDockerVulnerabilities(const std::vector<DockerVulnerability>& vulns);
    void performDockerAnalysis();
} 
#pragma once

#include <string>
#include <vector>

namespace ContainerAnalysis {
    enum class ContainerType {
        NONE,
        DOCKER,
        LXC,
        KUBERNETES,
        AWS_LAMBDA,
        AZURE_FUNCTIONS,
        UNKNOWN
    };
    
    struct ContainerInfo {
        ContainerType type;
        std::string id;
        std::string name;
        std::string image;
        std::vector<std::string> mounts;
        std::vector<std::string> capabilities;
        bool privileged;
        bool hostNetwork;
    };
    
    // Detect if running in a container environment and get container information
    ContainerInfo detectContainerEnvironment();
    
    // Analyze potential container escape vectors
    void analyzeContainerEscapeVectors(const ContainerInfo& container);
    
    // Convert container type enum to string
    std::string containerTypeToString(ContainerType type);
} 
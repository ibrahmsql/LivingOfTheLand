#pragma once

#include <string>
#include <vector>
#include <map>

namespace SystemAnalysis {
    struct SystemInfo {
        std::string hostname;
        std::string kernelVersion;
        std::string distribution;
        std::string architecture;
        std::string cpuInfo;
        std::string memoryInfo;
        std::string uptime;
    };
    
    struct UserInfo {
        std::string username;
        std::string uid;
        std::string gid;
        std::string groups;
        std::string homeDir;
        std::string shell;
    };
    
    struct FileInfo {
        std::string path;
        std::string owner;
        std::string group;
        std::string permissions;
        time_t lastModified;
        bool isWritable;
        bool isExecutable;
    };
    
    // System information gathering
    SystemInfo getSystemInfo();
    void displaySystemInfo(const SystemInfo& info);
    
    // User information gathering
    UserInfo getCurrentUserInfo();
    std::vector<UserInfo> getAllUsers();
    void displayUserInfo(const UserInfo& info);
    
    // File permission analysis
    std::vector<FileInfo> findWritableSystemFiles();
    std::vector<FileInfo> findUnownedFiles();
    std::vector<FileInfo> findRecentlyModifiedSystemFiles(int days);
    std::vector<FileInfo> findWritableConfigFiles();
    std::vector<FileInfo> findWritableScripts();
    
    // Environment analysis
    std::map<std::string, std::string> getEnvironmentVariables();
    std::vector<std::string> getPathDirectories();
    bool checkForDotInPath();
    std::string getLdPreload();
    std::string getLdLibraryPath();
    
    // Process analysis
    std::vector<std::string> getRunningProcesses();
    std::vector<std::string> getSystemServices();
    std::vector<std::string> getListeningPorts();
    
    // Security checks
    bool checkKernelRandomization();
    bool checkPtraceScope();
    std::vector<std::string> getCapabilities();
    
    // Display functions
    void performFullSystemAnalysis();
} 
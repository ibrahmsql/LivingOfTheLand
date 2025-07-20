#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <functional>

namespace FileUtils {
    // Structure to hold file permission details
    struct FilePermInfo {
        std::string path;
        std::string owner;
        std::string group;
        std::string permissions;
        bool hasSUID;
        bool hasSGID;
        bool hasSticky;
        time_t lastModified;
    };

    // Find all SUID files in the given path
    std::vector<FilePermInfo> findSUIDs(const std::string& path = "/");
    
    // Find all SGID files in the given path
    std::vector<FilePermInfo> findSGIDs(const std::string& path = "/");
    
    // Find all world-writable files in the given path
    std::vector<FilePermInfo> findWorldWritable(const std::string& path = "/");
    
    // Find files with specific permissions (using permission mask)
    std::vector<FilePermInfo> findFilesWithPermissions(const std::string& path, 
                                                      unsigned int permissionMask);
    
    // Find files owned by specific user
    std::vector<FilePermInfo> findFilesByOwner(const std::string& path, 
                                              const std::string& owner);
    
    // Find files modified within the last N days
    std::vector<FilePermInfo> findRecentlyModifiedFiles(const std::string& path, 
                                                       int days);
    
    // Search for files containing specific content
    std::vector<std::string> findFilesWithContent(const std::string& path, 
                                                 const std::string& content,
                                                 bool caseSensitive = true);
    
    // Check if a file is potentially exploitable (based on common patterns)
    bool isPotentiallyExploitable(const std::string& filePath);
    
    // Get detailed information about a file
    FilePermInfo getFileInfo(const std::string& filePath);
    
    // Custom file search with callback function
    std::vector<std::string> customFileSearch(
        const std::string& path,
        std::function<bool(const std::string&)> filterFunction);
}
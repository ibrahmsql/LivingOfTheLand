#include "suids.h"
#include "executils.h"
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fstream>
#include <regex>
#include <ctime>
#include <set>
#include <algorithm>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define RESET "\033[0m"

namespace fs = std::filesystem;

namespace FileUtils {

// Convert mode_t to permission string (like ls -l)
std::string modeToString(mode_t mode) {
    std::string result = "";
    
    // File type
    if (S_ISREG(mode)) result += "-";
    else if (S_ISDIR(mode)) result += "d";
    else if (S_ISLNK(mode)) result += "l";
    else if (S_ISCHR(mode)) result += "c";
    else if (S_ISBLK(mode)) result += "b";
    else if (S_ISFIFO(mode)) result += "p";
    else if (S_ISSOCK(mode)) result += "s";
    else result += "?";
    
    // User permissions
    result += (mode & S_IRUSR) ? "r" : "-";
    result += (mode & S_IWUSR) ? "w" : "-";
    result += (mode & S_IXUSR) ? 
              ((mode & S_ISUID) ? "s" : "x") : 
              ((mode & S_ISUID) ? "S" : "-");
    
    // Group permissions
    result += (mode & S_IRGRP) ? "r" : "-";
    result += (mode & S_IWGRP) ? "w" : "-";
    result += (mode & S_IXGRP) ? 
              ((mode & S_ISGID) ? "s" : "x") : 
              ((mode & S_ISGID) ? "S" : "-");
    
    // Other permissions
    result += (mode & S_IROTH) ? "r" : "-";
    result += (mode & S_IWOTH) ? "w" : "-";
    result += (mode & S_IXOTH) ? 
              ((mode & S_ISVTX) ? "t" : "x") : 
              ((mode & S_ISVTX) ? "T" : "-");
    
    return result;
}

// Get owner and group names from IDs
std::pair<std::string, std::string> getOwnerAndGroup(uid_t uid, gid_t gid) {
    std::string owner = std::to_string(uid);
    std::string group = std::to_string(gid);
    
    struct passwd* pw = getpwuid(uid);
    if (pw) {
        owner = pw->pw_name;
    }
    
    struct group* gr = getgrgid(gid);
    if (gr) {
        group = gr->gr_name;
    }
    
    return {owner, group};
}

// Get file information
FilePermInfo getFileInfo(const std::string& filePath) {
    FilePermInfo info;
    info.path = filePath;
    
    try {
        struct stat fileStat;
        if (stat(filePath.c_str(), &fileStat) == 0) {
            auto [owner, group] = getOwnerAndGroup(fileStat.st_uid, fileStat.st_gid);
            info.owner = owner;
            info.group = group;
            info.permissions = modeToString(fileStat.st_mode);
            info.hasSUID = (fileStat.st_mode & S_ISUID);
            info.hasSGID = (fileStat.st_mode & S_ISGID);
            info.hasSticky = (fileStat.st_mode & S_ISVTX);
            info.lastModified = fileStat.st_mtime;
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error getting file info for " << filePath 
                  << ": " << e.what() << RESET << std::endl;
    }
    
    return info;
}

// Find files with specific permissions recursively
std::vector<FilePermInfo> findFilesWithPermissions(const std::string& path, 
                                                 unsigned int permissionMask) {
    std::vector<FilePermInfo> matchingFiles;
    std::error_code ec;
    
    try {
        auto options = fs::directory_options::skip_permission_denied;
        auto iter = fs::recursive_directory_iterator(path, options, ec);
        
        if (ec) {
            std::cerr << RED << "Error creating directory iterator for " << path 
                      << ": " << ec.message() << RESET << std::endl;
            return matchingFiles;
        }
        
        for (auto it = iter; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            
            try {
                if (!fs::is_regular_file(it->path(), ec)) continue;
                if (ec) continue;
                
                if (access(it->path().c_str(), R_OK) != 0) continue;
                
                struct stat fileStat;
                if (stat(it->path().c_str(), &fileStat) == 0) {
                    if (fileStat.st_mode & permissionMask) {
                        FilePermInfo info = getFileInfo(it->path().string());
                        matchingFiles.push_back(info);
                    }
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error scanning files: " << e.what() << RESET << std::endl;
    }
    
    return matchingFiles;
}

// Find SUID files
std::vector<FilePermInfo> findSUIDs(const std::string& path) {
    return findFilesWithPermissions(path, S_ISUID);
}

// Find SGID files
std::vector<FilePermInfo> findSGIDs(const std::string& path) {
    return findFilesWithPermissions(path, S_ISGID);
}

// Find world-writable files
std::vector<FilePermInfo> findWorldWritable(const std::string& path) {
    return findFilesWithPermissions(path, S_IWOTH);
}

// Find files owned by specific user
std::vector<FilePermInfo> findFilesByOwner(const std::string& path, 
                                          const std::string& owner) {
    std::vector<FilePermInfo> matchingFiles;
    std::error_code ec;
    
    // Get UID from owner name
    uid_t ownerUid = -1;
    struct passwd* pw = getpwnam(owner.c_str());
    if (pw) {
        ownerUid = pw->pw_uid;
    } else {
        try {
            ownerUid = std::stoi(owner);
        } catch (...) {
            std::cerr << RED << "Invalid owner: " << owner << RESET << std::endl;
            return matchingFiles;
        }
    }
    
    try {
        auto options = fs::directory_options::skip_permission_denied;
        auto iter = fs::recursive_directory_iterator(path, options, ec);
        
        if (ec) {
            std::cerr << RED << "Error creating directory iterator for " << path 
                      << ": " << ec.message() << RESET << std::endl;
            return matchingFiles;
        }
        
        for (auto it = iter; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            
            try {
                if (!fs::is_regular_file(it->path(), ec)) continue;
                if (ec) continue;
                
                struct stat fileStat;
                if (stat(it->path().c_str(), &fileStat) == 0) {
                    if (fileStat.st_uid == ownerUid) {
                        FilePermInfo info = getFileInfo(it->path().string());
                        matchingFiles.push_back(info);
                    }
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error scanning files: " << e.what() << RESET << std::endl;
    }
    
    return matchingFiles;
}

// Find recently modified files
std::vector<FilePermInfo> findRecentlyModifiedFiles(const std::string& path, int days) {
    std::vector<FilePermInfo> matchingFiles;
    std::error_code ec;
    
    time_t now = time(nullptr);
    time_t cutoff = now - (days * 24 * 60 * 60);
    
    try {
        auto options = fs::directory_options::skip_permission_denied;
        auto iter = fs::recursive_directory_iterator(path, options, ec);
        
        if (ec) {
            std::cerr << RED << "Error creating directory iterator for " << path 
                      << ": " << ec.message() << RESET << std::endl;
            return matchingFiles;
        }
        
        for (auto it = iter; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            
            try {
                if (!fs::is_regular_file(it->path(), ec)) continue;
                if (ec) continue;
                
                struct stat fileStat;
                if (stat(it->path().c_str(), &fileStat) == 0) {
                    if (fileStat.st_mtime >= cutoff) {
                        FilePermInfo info = getFileInfo(it->path().string());
                        matchingFiles.push_back(info);
                    }
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error scanning files: " << e.what() << RESET << std::endl;
    }
    
    return matchingFiles;
}

// Find files with specific content
std::vector<std::string> findFilesWithContent(const std::string& path, 
                                            const std::string& content,
                                            bool caseSensitive) {
    std::vector<std::string> matchingFiles;
    std::error_code ec;
    
    try {
        auto options = fs::directory_options::skip_permission_denied;
        auto iter = fs::recursive_directory_iterator(path, options, ec);
        
        if (ec) {
            std::cerr << RED << "Error creating directory iterator for " << path 
                      << ": " << ec.message() << RESET << std::endl;
            return matchingFiles;
        }
        
        std::regex pattern(content, 
                          caseSensitive ? std::regex::ECMAScript : 
                                         (std::regex::ECMAScript | std::regex::icase));
        
        for (auto it = iter; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            
            try {
                if (!fs::is_regular_file(it->path(), ec)) continue;
                if (ec) continue;
                
                if (access(it->path().c_str(), R_OK) != 0) continue;
                
                std::ifstream file(it->path().string());
                if (!file.is_open()) continue;
                
                std::string line;
                bool found = false;
                
                while (std::getline(file, line) && !found) {
                    if (std::regex_search(line, pattern)) {
                        matchingFiles.push_back(it->path().string());
                        found = true;
                    }
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error scanning files: " << e.what() << RESET << std::endl;
    }
    
    return matchingFiles;
}

// Check if a file is potentially exploitable
bool isPotentiallyExploitable(const std::string& filePath) {
    FilePermInfo info = getFileInfo(filePath);
    
    // Check for SUID/SGID binaries
    if (info.hasSUID || info.hasSGID) {
        // Common exploitable SUID binaries
        static const std::set<std::string> knownExploitable = {
            "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv",
            "python", "perl", "ruby", "gdb", "man", "awk", "sed", "tcpdump"
        };
        
        std::string filename = fs::path(filePath).filename().string();
        if (knownExploitable.find(filename) != knownExploitable.end()) {
            return true;
        }
        
        // Check if world-writable
        if (info.permissions[8] == 'w') {
            return true;
        }
    }
    
    return false;
}

// Custom file search with callback function
std::vector<std::string> customFileSearch(
    const std::string& path,
    std::function<bool(const std::string&)> filterFunction) {
    
    std::vector<std::string> matchingFiles;
    std::error_code ec;
    
    try {
        auto options = fs::directory_options::skip_permission_denied;
        auto iter = fs::recursive_directory_iterator(path, options, ec);
        
        if (ec) {
            std::cerr << RED << "Error creating directory iterator for " << path 
                      << ": " << ec.message() << RESET << std::endl;
            return matchingFiles;
        }
        
        for (auto it = iter; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            
            try {
                if (filterFunction(it->path().string())) {
                    matchingFiles.push_back(it->path().string());
                }
            } catch (const std::exception& e) {
                continue;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error in custom file search: " << e.what() << RESET << std::endl;
    }
    
    return matchingFiles;
}

} // namespace FileUtils
#include "systemanalyzer.h"
#include "executils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <unistd.h>
#include <ctime>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace SystemAnalysis {

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

// System information gathering
SystemInfo getSystemInfo() {
    SystemInfo info;
    
    // Get hostname
    info.hostname = trim(execCommand("hostname 2>/dev/null"));
    
    // Get kernel version
    info.kernelVersion = trim(execCommand("uname -a 2>/dev/null"));
    
    // Get distribution info
    std::string distroInfo = execCommand("cat /etc/*-release 2>/dev/null");
    if (distroInfo.empty()) {
        distroInfo = execCommand("sw_vers 2>/dev/null"); // For macOS
    }
    info.distribution = trim(distroInfo);
    
    // Get architecture
    info.architecture = trim(execCommand("uname -m 2>/dev/null"));
    
    // Get CPU info
    std::string cpuInfo = execCommand("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1");
    if (cpuInfo.empty()) {
        cpuInfo = execCommand("sysctl -n machdep.cpu.brand_string 2>/dev/null"); // For macOS
    }
    info.cpuInfo = trim(cpuInfo);
    
    // Get memory info
    std::string memInfo = execCommand("cat /proc/meminfo 2>/dev/null | grep 'MemTotal'");
    if (memInfo.empty()) {
        memInfo = execCommand("sysctl -n hw.memsize 2>/dev/null | awk '{print $0/1024/1024 \" MB\"}'"); // For macOS
    }
    info.memoryInfo = trim(memInfo);
    
    // Get uptime
    std::string uptime = execCommand("uptime 2>/dev/null");
    info.uptime = trim(uptime);
    
    return info;
}

void displaySystemInfo(const SystemInfo& info) {
    std::cout << BOLD << BLUE << "[+] System Information:" << RESET << std::endl;
    
    std::cout << BLUE << "  [*] " << RESET << "Hostname: " << CYAN << info.hostname << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Kernel: " << CYAN << info.kernelVersion << RESET << std::endl;
    
    // Display distribution info in a more readable way
    std::istringstream distroStream(info.distribution);
    std::string line;
    bool foundDistro = false;
    while (std::getline(distroStream, line)) {
        if (line.find("PRETTY_NAME") != std::string::npos || 
            line.find("ProductName") != std::string::npos ||
            line.find("DISTRIB_DESCRIPTION") != std::string::npos) {
            std::cout << BLUE << "  [*] " << RESET << "Distribution: " << CYAN << line.substr(line.find("=") + 1) << RESET << std::endl;
            foundDistro = true;
            break;
        }
    }
    
    if (!foundDistro) {
        std::cout << BLUE << "  [*] " << RESET << "Distribution: " << CYAN << "Unknown" << RESET << std::endl;
    }
    
    std::cout << BLUE << "  [*] " << RESET << "Architecture: " << CYAN << info.architecture << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "CPU: " << CYAN << info.cpuInfo << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Memory: " << CYAN << info.memoryInfo << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Uptime: " << CYAN << info.uptime << RESET << std::endl;
}

// User information gathering
UserInfo getCurrentUserInfo() {
    UserInfo info;
    
    // Get current username
    info.username = trim(execCommand("whoami 2>/dev/null"));
    
    // Get user ID and group ID
    std::string idOutput = execCommand("id 2>/dev/null");
    std::regex uidRegex("uid=(\\d+)");
    std::regex gidRegex("gid=(\\d+)");
    std::regex groupsRegex("groups=(.+)");
    
    std::smatch match;
    if (std::regex_search(idOutput, match, uidRegex)) {
        info.uid = match[1].str();
    }
    
    if (std::regex_search(idOutput, match, gidRegex)) {
        info.gid = match[1].str();
    }
    
    if (std::regex_search(idOutput, match, groupsRegex)) {
        info.groups = match[1].str();
    }
    
    // Get home directory
    info.homeDir = trim(execCommand("echo $HOME 2>/dev/null"));
    
    // Get shell
    info.shell = trim(execCommand("echo $SHELL 2>/dev/null"));
    
    return info;
}

std::vector<UserInfo> getAllUsers() {
    std::vector<UserInfo> users;
    
    std::string passwdContent = execCommand("cat /etc/passwd 2>/dev/null");
    std::istringstream passwdStream(passwdContent);
    std::string line;
    
    while (std::getline(passwdStream, line)) {
        std::istringstream lineStream(line);
        std::string field;
        std::vector<std::string> fields;
        
        while (std::getline(lineStream, field, ':')) {
            fields.push_back(field);
        }
        
        if (fields.size() >= 7) {
            UserInfo user;
            user.username = fields[0];
            user.uid = fields[2];
            user.gid = fields[3];
            user.homeDir = fields[5];
            user.shell = fields[6];
            
            // Skip system users
            if (std::stoi(user.uid) >= 1000 || user.username == "root") {
                users.push_back(user);
            }
        }
    }
    
    return users;
}

void displayUserInfo(const UserInfo& info) {
    std::cout << BOLD << BLUE << "[+] User Information:" << RESET << std::endl;
    
    std::cout << BLUE << "  [*] " << RESET << "Username: " << CYAN << info.username << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "User ID: " << CYAN << info.uid << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Group ID: " << CYAN << info.gid << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Groups: " << CYAN << info.groups << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Home Directory: " << CYAN << info.homeDir << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Shell: " << CYAN << info.shell << RESET << std::endl;
    
    // Check if user is in sudo group
    if (info.groups.find("sudo") != std::string::npos || 
        info.groups.find("wheel") != std::string::npos || 
        info.groups.find("admin") != std::string::npos) {
        std::cout << YELLOW << "  [!] " << RESET << "User has sudo privileges!" << std::endl;
    }
    
    // Check sudo permissions without password (non-interactive)
    std::string sudoOutput = execCommand("sudo -n -l 2>/dev/null");
    if (!sudoOutput.empty() && sudoOutput.find("not allowed") == std::string::npos && sudoOutput.find("password") == std::string::npos) {
        std::cout << RED << "  [!] " << RESET << "User can run sudo commands without password!" << std::endl;
        std::cout << sudoOutput << std::endl;
    } else {
        std::cout << YELLOW << "  [*] " << RESET << "Sudo access requires password or not available" << std::endl;
    }
}

// File permission analysis
std::vector<FileInfo> findWritableSystemFiles() {
    std::vector<FileInfo> files;
    
    std::string output = execCommand("find /etc /bin /sbin /usr/bin /usr/sbin -type f -writable 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        FileInfo file;
        file.path = line;
        
        // Get file owner, group, and permissions
        std::string lsOutput = execCommand("ls -la " + file.path + " 2>/dev/null");
        std::istringstream lsStream(lsOutput);
        std::string lsLine;
        
        if (std::getline(lsStream, lsLine)) {
            std::istringstream lineStream(lsLine);
            std::string perms, links, owner, group;
            
            lineStream >> perms >> links >> owner >> group;
            
            file.permissions = perms;
            file.owner = owner;
            file.group = group;
            file.isWritable = true;
            file.isExecutable = (perms[3] == 'x' || perms[6] == 'x' || perms[9] == 'x');
            
            files.push_back(file);
        }
    }
    
    return files;
}

std::vector<FileInfo> findUnownedFiles() {
    std::vector<FileInfo> files;
    
    std::string output = execCommand("find / -nouser -o -nogroup 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        FileInfo file;
        file.path = line;
        
        // Get file owner, group, and permissions
        std::string lsOutput = execCommand("ls -la " + file.path + " 2>/dev/null");
        std::istringstream lsStream(lsOutput);
        std::string lsLine;
        
        if (std::getline(lsStream, lsLine)) {
            std::istringstream lineStream(lsLine);
            std::string perms, links, owner, group;
            
            lineStream >> perms >> links >> owner >> group;
            
            file.permissions = perms;
            file.owner = owner;
            file.group = group;
            file.isWritable = (perms[2] == 'w' || perms[5] == 'w' || perms[8] == 'w');
            file.isExecutable = (perms[3] == 'x' || perms[6] == 'x' || perms[9] == 'x');
            
            files.push_back(file);
        }
    }
    
    return files;
}

std::vector<FileInfo> findRecentlyModifiedSystemFiles(int days) {
    std::vector<FileInfo> files;
    
    std::string output = execCommand("find /etc /bin /sbin /usr/bin /usr/sbin -type f -mtime -" + std::to_string(days) + " 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        FileInfo file;
        file.path = line;
        
        // Get file owner, group, and permissions
        std::string lsOutput = execCommand("ls -la " + file.path + " 2>/dev/null");
        std::istringstream lsStream(lsOutput);
        std::string lsLine;
        
        if (std::getline(lsStream, lsLine)) {
            std::istringstream lineStream(lsLine);
            std::string perms, links, owner, group, size, month, day, time;
            
            lineStream >> perms >> links >> owner >> group >> size >> month >> day >> time;
            
            file.permissions = perms;
            file.owner = owner;
            file.group = group;
            file.isWritable = (perms[2] == 'w' || perms[5] == 'w' || perms[8] == 'w');
            file.isExecutable = (perms[3] == 'x' || perms[6] == 'x' || perms[9] == 'x');
            
            // Get current time
            std::time_t now = std::time(nullptr);
            file.lastModified = now - (days * 24 * 60 * 60); // Approximate
            
            files.push_back(file);
        }
    }
    
    return files;
}

std::vector<FileInfo> findWritableConfigFiles() {
    std::vector<FileInfo> files;
    
    std::string output = execCommand("find /etc -type f -writable 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        FileInfo file;
        file.path = line;
        
        // Get file owner, group, and permissions
        std::string lsOutput = execCommand("ls -la " + file.path + " 2>/dev/null");
        std::istringstream lsStream(lsOutput);
        std::string lsLine;
        
        if (std::getline(lsStream, lsLine)) {
            std::istringstream lineStream(lsLine);
            std::string perms, links, owner, group;
            
            lineStream >> perms >> links >> owner >> group;
            
            file.permissions = perms;
            file.owner = owner;
            file.group = group;
            file.isWritable = true;
            file.isExecutable = (perms[3] == 'x' || perms[6] == 'x' || perms[9] == 'x');
            
            files.push_back(file);
        }
    }
    
    return files;
}

std::vector<FileInfo> findWritableScripts() {
    std::vector<FileInfo> files;
    
    std::string output = execCommand("find / -type f -name '*.sh' -perm -o+w 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        FileInfo file;
        file.path = line;
        
        // Get file owner, group, and permissions
        std::string lsOutput = execCommand("ls -la " + file.path + " 2>/dev/null");
        std::istringstream lsStream(lsOutput);
        std::string lsLine;
        
        if (std::getline(lsStream, lsLine)) {
            std::istringstream lineStream(lsLine);
            std::string perms, links, owner, group;
            
            lineStream >> perms >> links >> owner >> group;
            
            file.permissions = perms;
            file.owner = owner;
            file.group = group;
            file.isWritable = true;
            file.isExecutable = (perms[3] == 'x' || perms[6] == 'x' || perms[9] == 'x');
            
            files.push_back(file);
        }
    }
    
    return files;
}

// Environment analysis
std::map<std::string, std::string> getEnvironmentVariables() {
    std::map<std::string, std::string> envVars;
    
    std::string output = execCommand("printenv 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string name = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            envVars[name] = value;
        }
    }
    
    return envVars;
}

std::vector<std::string> getPathDirectories() {
    std::vector<std::string> pathDirs;
    
    std::string pathEnv = execCommand("echo $PATH 2>/dev/null");
    std::istringstream pathStream(pathEnv);
    std::string dir;
    
    while (std::getline(pathStream, dir, ':')) {
        pathDirs.push_back(dir);
    }
    
    return pathDirs;
}

bool checkForDotInPath() {
    std::string output = execCommand("echo $PATH | tr ':' '\\n' | grep '^\\.$' 2>/dev/null");
    return !output.empty();
}

std::string getLdPreload() {
    return trim(execCommand("echo $LD_PRELOAD 2>/dev/null"));
}

std::string getLdLibraryPath() {
    return trim(execCommand("echo $LD_LIBRARY_PATH 2>/dev/null"));
}

// Process analysis
std::vector<std::string> getRunningProcesses() {
    std::vector<std::string> processes;
    
    std::string output = execCommand("ps aux 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    // Skip header line
    std::getline(outputStream, line);
    
    while (std::getline(outputStream, line)) {
        processes.push_back(line);
    }
    
    return processes;
}

std::vector<std::string> getSystemServices() {
    std::vector<std::string> services;
    
    // Try systemctl first (for systemd-based systems)
    std::string output = execCommand("systemctl list-units --type=service 2>/dev/null");
    if (!output.empty()) {
        std::istringstream outputStream(output);
        std::string line;
        
        while (std::getline(outputStream, line)) {
            if (line.find(".service") != std::string::npos) {
                services.push_back(line);
            }
        }
    } else {
        // Try service command (for SysV init systems)
        output = execCommand("service --status-all 2>/dev/null");
        if (!output.empty()) {
            std::istringstream outputStream(output);
            std::string line;
            
            while (std::getline(outputStream, line)) {
                services.push_back(line);
            }
        } else {
            // Try launchctl for macOS
            output = execCommand("launchctl list 2>/dev/null");
            if (!output.empty()) {
                std::istringstream outputStream(output);
                std::string line;
                
                while (std::getline(outputStream, line)) {
                    services.push_back(line);
                }
            }
        }
    }
    
    return services;
}

std::vector<std::string> getListeningPorts() {
    std::vector<std::string> ports;
    
    // Try netstat first
    std::string output = execCommand("netstat -tulpn 2>/dev/null");
    if (output.find("Active Internet connections") != std::string::npos) {
        std::istringstream outputStream(output);
        std::string line;
        
        // Skip header lines
        while (std::getline(outputStream, line) && line.find("Proto") == std::string::npos) {}
        
        while (std::getline(outputStream, line)) {
            if (line.find("LISTEN") != std::string::npos) {
                ports.push_back(line);
            }
        }
    } else {
        // Try ss command
        output = execCommand("ss -tulpn 2>/dev/null");
        if (!output.empty()) {
            std::istringstream outputStream(output);
            std::string line;
            
            // Skip header line
            std::getline(outputStream, line);
            
            while (std::getline(outputStream, line)) {
                if (line.find("LISTEN") != std::string::npos) {
                    ports.push_back(line);
                }
            }
        } else {
            // Try lsof for macOS
            output = execCommand("lsof -i -n -P | grep LISTEN 2>/dev/null");
            if (!output.empty()) {
                std::istringstream outputStream(output);
                std::string line;
                
                while (std::getline(outputStream, line)) {
                    ports.push_back(line);
                }
            }
        }
    }
    
    return ports;
}

// Security checks
bool checkKernelRandomization() {
    std::string output = execCommand("cat /proc/sys/kernel/randomize_va_space 2>/dev/null");
    if (!output.empty()) {
        int value = std::stoi(output);
        return value > 0;
    }
    
    return false;
}

bool checkPtraceScope() {
    std::string output = execCommand("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null");
    if (!output.empty()) {
        int value = std::stoi(output);
        return value > 0;
    }
    
    return false;
}

std::vector<std::string> getCapabilities() {
    std::vector<std::string> capabilities;
    
    std::string output = execCommand("getcap -r / 2>/dev/null");
    std::istringstream outputStream(output);
    std::string line;
    
    while (std::getline(outputStream, line)) {
        capabilities.push_back(line);
    }
    
    return capabilities;
}

// Display functions
void performFullSystemAnalysis() {
    std::cout << BOLD << BLUE << "\n===== System Analysis =====" << RESET << std::endl;
    
    // Display system information
    SystemInfo sysInfo = getSystemInfo();
    displaySystemInfo(sysInfo);
    
    // Display user information
    UserInfo userInfo = getCurrentUserInfo();
    displayUserInfo(userInfo);
    
    // Check for writable system files
    std::vector<FileInfo> writableSysFiles = findWritableSystemFiles();
    if (!writableSysFiles.empty()) {
        std::cout << BOLD << RED << "\n[!] Found " << writableSysFiles.size() << " writable system files:" << RESET << std::endl;
        for (const auto& file : writableSysFiles) {
            std::cout << "  " << file.path << " (" << file.permissions << " " << file.owner << ":" << file.group << ")" << std::endl;
        }
    }
    
    // Check for unowned files
    std::vector<FileInfo> unownedFiles = findUnownedFiles();
    if (!unownedFiles.empty()) {
        std::cout << BOLD << RED << "\n[!] Found " << unownedFiles.size() << " unowned files:" << RESET << std::endl;
        for (const auto& file : unownedFiles) {
            std::cout << "  " << file.path << " (" << file.permissions << " " << file.owner << ":" << file.group << ")" << std::endl;
        }
    }
    
    // Check for recently modified system files
    std::vector<FileInfo> recentSysFiles = findRecentlyModifiedSystemFiles(7);
    if (!recentSysFiles.empty()) {
        std::cout << BOLD << YELLOW << "\n[!] Found " << recentSysFiles.size() << " recently modified system files:" << RESET << std::endl;
        for (const auto& file : recentSysFiles) {
            std::cout << "  " << file.path << " (" << file.permissions << " " << file.owner << ":" << file.group << ")" << std::endl;
        }
    }
    
    // Check for writable config files
    std::vector<FileInfo> writableConfigFiles = findWritableConfigFiles();
    if (!writableConfigFiles.empty()) {
        std::cout << BOLD << RED << "\n[!] Found " << writableConfigFiles.size() << " writable config files:" << RESET << std::endl;
        for (const auto& file : writableConfigFiles) {
            std::cout << "  " << file.path << " (" << file.permissions << " " << file.owner << ":" << file.group << ")" << std::endl;
        }
    }
    
    // Check for writable scripts
    std::vector<FileInfo> writableScripts = findWritableScripts();
    if (!writableScripts.empty()) {
        std::cout << BOLD << RED << "\n[!] Found " << writableScripts.size() << " writable scripts:" << RESET << std::endl;
        for (const auto& file : writableScripts) {
            std::cout << "  " << file.path << " (" << file.permissions << " " << file.owner << ":" << file.group << ")" << std::endl;
        }
    }
    
    // Check environment variables
    std::map<std::string, std::string> envVars = getEnvironmentVariables();
    std::cout << BOLD << BLUE << "\n[+] Environment Variables:" << RESET << std::endl;
    
    // Check for dangerous environment variables
    if (!getLdPreload().empty()) {
        std::cout << BOLD << RED << "  [!] LD_PRELOAD is set: " << getLdPreload() << RESET << std::endl;
    }
    
    if (!getLdLibraryPath().empty()) {
        std::cout << BOLD << YELLOW << "  [!] LD_LIBRARY_PATH is set: " << getLdLibraryPath() << RESET << std::endl;
    }
    
    if (checkForDotInPath()) {
        std::cout << BOLD << RED << "  [!] Current directory (.) is in PATH!" << RESET << std::endl;
    }
    
    // Display PATH directories
    std::vector<std::string> pathDirs = getPathDirectories();
    std::cout << BLUE << "  [*] " << RESET << "PATH directories:" << std::endl;
    for (const auto& dir : pathDirs) {
        std::cout << "    " << dir << std::endl;
    }
    
    // Check for listening ports
    std::vector<std::string> listeningPorts = getListeningPorts();
    if (!listeningPorts.empty()) {
        std::cout << BOLD << BLUE << "\n[+] Listening Ports:" << RESET << std::endl;
        for (const auto& port : listeningPorts) {
            std::cout << "  " << port << std::endl;
        }
    }
    
    // Check for kernel security features
    std::cout << BOLD << BLUE << "\n[+] Kernel Security Features:" << RESET << std::endl;
    
    if (checkKernelRandomization()) {
        std::cout << GREEN << "  [✓] " << RESET << "Address Space Layout Randomization (ASLR) is enabled" << std::endl;
    } else {
        std::cout << RED << "  [!] " << RESET << "Address Space Layout Randomization (ASLR) is disabled!" << std::endl;
    }
    
    if (checkPtraceScope()) {
        std::cout << GREEN << "  [✓] " << RESET << "Ptrace protection is enabled" << std::endl;
    } else {
        std::cout << RED << "  [!] " << RESET << "Ptrace protection is disabled!" << std::endl;
    }
    
    // Check for capabilities
    std::vector<std::string> capabilities = getCapabilities();
    if (!capabilities.empty()) {
        std::cout << BOLD << BLUE << "\n[+] Files with Capabilities:" << RESET << std::endl;
        for (const auto& cap : capabilities) {
            std::cout << "  " << cap << std::endl;
        }
    }
}

} // namespace SystemAnalysis
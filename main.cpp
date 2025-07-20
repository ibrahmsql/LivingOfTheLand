#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <string>
#include <vector>
#include <thread>
#include <unistd.h>
#include "core/init.h"
#include "tools/executils.h"
#include "tools/suids.h"
#include "tools/web.h"
#include "tools/cronanalyzer.h"
#include "tools/kernelvulnscan.h"
#include "tools/sudoanalyzer.h"
#include "tools/containeranalyzer.h"
#include "tools/networkanalyzer.h"
#include "tools/cveanalyzer.h"
#include "tools/systemanalyzer.h"
#include "tools/dockeranalyzer.h"

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define UNDERLINE "\033[4m"

// Function to get current timestamp as string
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Function to display a section header
void displaySectionHeader(const std::string& title) {
    std::cout << std::endl;
    std::cout << BOLD << BLUE << "===================================================================" << RESET << std::endl;
    std::cout << BOLD << BLUE << "   " << title << RESET << std::endl;
    std::cout << BOLD << BLUE << "===================================================================" << RESET << std::endl;
    std::cout << std::endl;
}

// Function to display progress
void displayProgress(const std::string& message) {
    std::cout << CYAN << "[*] " << RESET << message << "..." << std::endl;
}

// Function to display a success message
void displaySuccess(const std::string& message) {
    std::cout << GREEN << "[+] " << RESET << message << std::endl;
}

// Function to display a warning message
void displayWarning(const std::string& message) {
    std::cout << YELLOW << "[!] " << RESET << message << std::endl;
}

// Function to display an error message
void displayError(const std::string& message) {
    std::cout << RED << "[-] " << RESET << message << std::endl;
}

// Function to display the banner
void displayBanner() {
    std::cout << BOLD << BLUE << R"(
  __       ______  ______  __       
 /\ \     /\  __ \/\__  _\/\ \      
 \ \ \____\ \ \/\ \/_/\ \/\ \ \____ 
  \ \_____\\ \_____\ \ \_\ \ \_____\
   \/_____/ \/_____/  \/_/  \/_____/
                                    
)" << RESET << std::endl;

    std::cout << BOLD << YELLOW << "    LIVING OFF THE LAND TOOLKIT v2.0" << RESET << std::endl;
    std::cout << CYAN << "    System Security Analysis & Privilege Escalation" << RESET << std::endl;
    std::cout << std::endl;
    
    // Get current date
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream dateStream;
    dateStream << std::put_time(std::localtime(&time), "%Y-%m-%d");
    
    std::cout << BOLD << "    Features: " << RESET;
    std::cout << "System Analysis | Security Scanning | Privilege Escalation | Container Analysis" << std::endl;
    std::cout << std::endl;
    
    std::cout << BOLD << "    Author: " << RESET << "ibrahimsql" << "  ";
    std::cout << BOLD << "Date: " << RESET << dateStream.str() << std::endl;
    
    std::cout << RED << "    [!] " << RESET << "Use this tool only on systems you are authorized to test!" << std::endl;
    std::cout << std::endl;
    
    std::cout << BOLD << BLUE << "========================================================" << RESET << std::endl;
    std::cout << std::endl;
}

// Function to execute Linux commands and display their output
void executeAndDisplayCommand(const std::string& title, const std::string& command) {
    std::cout << BOLD << BLUE << "[+] " << title << ":" << RESET << std::endl;
    std::string output = ExecUtils::execCommand(command + " 2>/dev/null");
    if (!output.empty()) {
        std::cout << output << std::endl;
    } else {
        std::cout << YELLOW << "  No output or command failed" << RESET << std::endl;
    }
    std::cout << std::endl;
}

// Function to run advanced system checks
void runAdvancedSystemChecks() {
    displaySectionHeader("ADVANCED SYSTEM CHECKS");
    
    // System info commands
    executeAndDisplayCommand("Kernel Information", "uname -a");
    executeAndDisplayCommand("Distribution Information", "cat /etc/*-release 2>/dev/null || sw_vers");
    executeAndDisplayCommand("Kernel Version", "cat /proc/version 2>/dev/null");
    executeAndDisplayCommand("Hostname Information", "hostnamectl 2>/dev/null");
    executeAndDisplayCommand("Kernel Parameters", "sysctl -a 2>/dev/null | grep -i kernel | head -20");
    executeAndDisplayCommand("Kernel Configuration", "cat /boot/config-$(uname -r) 2>/dev/null | head -20");
    executeAndDisplayCommand("Kernel Command Line", "cat /proc/cmdline 2>/dev/null");
    executeAndDisplayCommand("Loaded Modules", "lsmod 2>/dev/null | head -20");
    executeAndDisplayCommand("Kernel ASLR Setting", "cat /proc/sys/kernel/randomize_va_space 2>/dev/null");
    executeAndDisplayCommand("Ptrace Scope Setting", "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null");
    
    // User info commands
    executeAndDisplayCommand("Current User", "id");
    executeAndDisplayCommand("Current User Name", "whoami");
    executeAndDisplayCommand("User Groups", "groups");
    executeAndDisplayCommand("Password File (First 10 lines)", "cat /etc/passwd 2>/dev/null | head -10");
    executeAndDisplayCommand("Shadow File (If readable)", "cat /etc/shadow 2>/dev/null | head -10");
    executeAndDisplayCommand("Last Logged In Users", "last 2>/dev/null | head -10");
    executeAndDisplayCommand("Currently Logged In Users", "w 2>/dev/null");
    executeAndDisplayCommand("Sudoers Configuration", "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20");
    executeAndDisplayCommand("Sudoers.d Directory", "ls -la /etc/sudoers.d/ 2>/dev/null");
    executeAndDisplayCommand("Sudo Privileges (No Password)", "sudo -l -n 2>/dev/null");
    executeAndDisplayCommand("TTY Processes", "ps aux 2>/dev/null | grep tty | head -10");
    executeAndDisplayCommand("User Shells", "cut -d: -f1,7 /etc/passwd 2>/dev/null | head -10");
    
    // Package info commands
    executeAndDisplayCommand("Installed Packages (Debian/Ubuntu - First 10)", "dpkg -l 2>/dev/null | head -10");
    executeAndDisplayCommand("Installed Packages (RHEL/CentOS - First 10)", "rpm -qa 2>/dev/null | head -10");
    executeAndDisplayCommand("Installed Packages (macOS - First 10)", "brew list 2>/dev/null | head -10");
    
    // Network info commands
    executeAndDisplayCommand("Network Interfaces", "ip a 2>/dev/null || ifconfig 2>/dev/null");
    executeAndDisplayCommand("Listening Ports", "netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null");
    executeAndDisplayCommand("DNS Configuration", "cat /etc/resolv.conf 2>/dev/null");
    executeAndDisplayCommand("Hosts File", "cat /etc/hosts 2>/dev/null");
    executeAndDisplayCommand("Routing Table", "route -n 2>/dev/null || netstat -rn 2>/dev/null");
    
    // Process info commands
    executeAndDisplayCommand("Running Processes (First 10)", "ps aux 2>/dev/null | head -10");
    executeAndDisplayCommand("System Services (First 10)", "systemctl list-units --type=service 2>/dev/null | head -10 || service --status-all 2>/dev/null | head -10 || launchctl list 2>/dev/null | head -10");
    
    // File system info commands
    executeAndDisplayCommand("Mounted Filesystems", "mount 2>/dev/null");
    executeAndDisplayCommand("Disk Usage", "df -h 2>/dev/null");
    
    // Special files
    executeAndDisplayCommand("SUID Files (First 10)", "find / -perm -4000 -type f 2>/dev/null | head -10");
    executeAndDisplayCommand("SGID Files (First 10)", "find / -perm -2000 -type f 2>/dev/null | head -10");
    executeAndDisplayCommand("World-Writable Directories (First 10)", "find / -writable -type d 2>/dev/null | head -10");
    executeAndDisplayCommand("Root Directory", "ls -la /root 2>/dev/null");
    executeAndDisplayCommand("Cron Jobs", "ls -la /var/spool/cron/ 2>/dev/null || ls -la /var/spool/cron/crontabs/ 2>/dev/null");
    
    // Environment info commands
    executeAndDisplayCommand("PATH Environment Variable", "echo $PATH");
    executeAndDisplayCommand("LD_PRELOAD Environment Variable", "echo $LD_PRELOAD");
    executeAndDisplayCommand("LD_LIBRARY_PATH Environment Variable", "echo $LD_LIBRARY_PATH");
    executeAndDisplayCommand("Environment Variables (First 20)", "printenv | head -20");
    executeAndDisplayCommand("Bash Type", "type -a bash");
    executeAndDisplayCommand("Shell Type", "type -a sh");
    
    // Cron job info
    executeAndDisplayCommand("User Crontab", "crontab -l 2>/dev/null");
    executeAndDisplayCommand("System Crontab", "cat /etc/crontab 2>/dev/null");
    executeAndDisplayCommand("Cron Directories", "ls -la /etc/cron.* 2>/dev/null");
    executeAndDisplayCommand("Writable Cron Directories", "find /etc/cron* -writable -exec ls -ld {} \\; 2>/dev/null");
    
    // Hidden files
    executeAndDisplayCommand("Hidden Files in Root (First 10)", "ls -la /root/.* 2>/dev/null | head -10");
    executeAndDisplayCommand("Hidden Files in Home Directories (First 10)", "ls -la /home/*/.* 2>/dev/null | head -10");
    executeAndDisplayCommand("Writable Hidden Files in Root", "find /root -type f -name \".*\" -writable 2>/dev/null | head -10");
    
    // Shell info
    executeAndDisplayCommand("Current Shell", "echo $SHELL");
    executeAndDisplayCommand("Bash Version", "bash --version 2>/dev/null | head -1");
    executeAndDisplayCommand("Zsh Version", "zsh --version 2>/dev/null");
    executeAndDisplayCommand("Dash Version", "dash --version 2>/dev/null");
    
    // Network service info
    executeAndDisplayCommand("Network Services", "netstat -tulpen 2>/dev/null || ss -tulpen 2>/dev/null");
    executeAndDisplayCommand("Hosts Allow", "cat /etc/hosts.allow 2>/dev/null");
    executeAndDisplayCommand("Hosts Deny", "cat /etc/hosts.deny 2>/dev/null");
    executeAndDisplayCommand("Running Network Services", "ps aux 2>/dev/null | grep -E 'apache|nginx|mysql|postgres|ssh|vsftpd|cupsd' | grep -v grep");
    executeAndDisplayCommand("SSH Version", "ssh -V 2>&1");
    executeAndDisplayCommand("SSH Configuration", "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'");
    
    // Log files
    executeAndDisplayCommand("Log Directory", "ls -la /var/log/ 2>/dev/null | head -10");
    executeAndDisplayCommand("Auth Log (Last 5 lines)", "tail -n 5 /var/log/auth.log 2>/dev/null");
    executeAndDisplayCommand("Syslog (Last 5 lines)", "tail -n 5 /var/log/syslog 2>/dev/null");
    executeAndDisplayCommand("Secure Log (Last 5 lines)", "tail -n 5 /var/log/secure 2>/dev/null");
    
    // macOS specific checks
    executeAndDisplayCommand("macOS System Integrity Protection", "csrutil status 2>/dev/null");
    executeAndDisplayCommand("macOS Gatekeeper Status", "spctl --status 2>/dev/null");
    executeAndDisplayCommand("macOS Launch Agents (User)", "ls ~/Library/LaunchAgents/ 2>/dev/null");
    executeAndDisplayCommand("macOS Launch Agents (System)", "ls /Library/LaunchAgents/ 2>/dev/null");
    executeAndDisplayCommand("macOS Launch Daemons", "ls /Library/LaunchDaemons/ 2>/dev/null");
    
    // Package manager permission issues
    executeAndDisplayCommand("Brew Permission Issues", "brew list 2>&1 | grep -i permission | head -5");
    executeAndDisplayCommand("Pip Cache Directory", "ls -ld ~/.cache/pip 2>/dev/null");
    executeAndDisplayCommand("NPM Cache Directory", "ls -ld ~/.cache/npm 2>/dev/null");
    
    // Extended checks
    executeAndDisplayCommand("World-Writable Root-Owned Files", "find / -type f -exec ls -la {} \\; 2>/dev/null | grep 'root.*root.*-rwxrwxrwx' | head -10");
    executeAndDisplayCommand("World-Writable Directories", "find / -type d -perm -o+w -exec ls -ld {} \\; 2>/dev/null | head -10");
    executeAndDisplayCommand("Root-Owned Writable Files", "find / -user root -perm -u=w -exec ls -ld {} \\; 2>/dev/null | head -10");
    executeAndDisplayCommand("Writable System Binaries", "find /usr/bin -perm -o+w -type f 2>/dev/null | head -10");
    executeAndDisplayCommand("Writable Environment Files", "find /root -name \".*\" -perm -o+w 2>/dev/null | head -10");
    executeAndDisplayCommand("Files Writable by Current User but Owned by Others", "find / -writable ! -user $(whoami) 2>/dev/null | head -10");
    executeAndDisplayCommand("Writable Sudoers Files", "find /etc/sudoers* -perm -o+w 2>/dev/null");
    executeAndDisplayCommand("Unowned Files", "find / -nouser -o -nogroup 2>/dev/null | head -10");
    executeAndDisplayCommand("SUID Risky Binaries", "find / -perm -4000 -type f \\( -name cp -o -name mv -o -name tar -o -name unzip -o -name zip \\) 2>/dev/null");
    executeAndDisplayCommand("Files with Elevated Capabilities", "getcap -r / 2>/dev/null | head -10");
    executeAndDisplayCommand("Capabilities Information", "capsh --print 2>/dev/null");
    executeAndDisplayCommand("Writable Init.d Scripts", "find /etc/init.d -type f -perm -o+w 2>/dev/null");
    executeAndDisplayCommand("Root Processes with Open Network Sockets", "lsof -i -n -P 2>/dev/null | grep root | head -10");
    executeAndDisplayCommand("Writable Open Files", "lsof 2>/dev/null | grep \"w\" | head -10");
    executeAndDisplayCommand("Writable Mounts", "mount 2>/dev/null | grep 'rw' | head -10");
    executeAndDisplayCommand("Users with Empty Passwords", "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null");
    executeAndDisplayCommand("World-Readable/Writable Files", "find / -type f -perm -o+rwx -exec ls -ld {} \\; 2>/dev/null | head -10");
    executeAndDisplayCommand("Vulnerable Setuid Scripts", "find / -type f -name '*.pl' -perm -4000 2>/dev/null || find / -type f -name '*.py' -perm -4000 2>/dev/null");
    executeAndDisplayCommand("Temp Directory Permissions", "ls -ld /tmp /var/tmp /dev/shm 2>/dev/null");
    executeAndDisplayCommand("Symbolic Links to Writable Locations", "find / -type l -exec ls -ld {} \\; 2>/dev/null | grep '->' | grep -E ' /tmp/| /var/tmp/| /dev/shm/' | head -10");
}

// Function to run all checks automatically
void runAllChecks() {
    // Display welcome banner
    displayBanner();
    
    std::cout << BOLD << GREEN << "[" << getCurrentTimestamp() << "] " 
              << "Starting automatic system enumeration..." << RESET << std::endl;
    
    // System Information
    displaySectionHeader("SYSTEM INFORMATION");
    displayProgress("Checking system dependencies");
    Init::checkDependencies();

    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // System Analysis
    displaySectionHeader("SYSTEM ANALYSIS");
    displayProgress("Performing system analysis");
    SystemAnalysis::performFullSystemAnalysis();
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Docker Analysis
    displaySectionHeader("DOCKER ANALYSIS");
    displayProgress("Performing Docker analysis");
    DockerAnalysis::performDockerAnalysis();
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // File Permission Analysis
    displaySectionHeader("FILE PERMISSION ANALYSIS");
    
    displayProgress("Searching for SUID binaries");
    auto suidFiles = FileUtils::findSUIDs();
    
    std::cout << std::endl;
    displaySuccess("Found " + std::to_string(suidFiles.size()) + " SUID binaries");
    
    for (const auto& file : suidFiles) {
        std::cout << YELLOW << "  " << file.path << RESET << std::endl;
        std::cout << "    Owner: " << CYAN << file.owner << RESET 
                << ", Group: " << CYAN << file.group << RESET 
                << ", Permissions: " << CYAN << file.permissions << RESET << std::endl;
                
        if (FileUtils::isPotentiallyExploitable(file.path)) {
            std::cout << RED << "    [!] Potentially exploitable!" << RESET << std::endl;
        }
        std::cout << std::endl;
    }
    
    displayProgress("Searching for world-writable files in /etc");
    auto worldWritableFiles = FileUtils::findWorldWritable("/etc");

    std::cout << std::endl;
    displaySuccess("Found " + std::to_string(worldWritableFiles.size()) + " world-writable files in /etc");
    
    for (const auto& file : worldWritableFiles) {
        std::cout << YELLOW << "  " << file.path << RESET << std::endl;
        std::cout << "    Owner: " << CYAN << file.owner << RESET 
                << ", Group: " << CYAN << file.group << RESET 
                << ", Permissions: " << CYAN << file.permissions << RESET << std::endl;
        std::cout << std::endl;
    }
    
    displayProgress("Searching for recently modified files");
    auto recentFiles = FileUtils::findRecentlyModifiedFiles("/etc", 7); // Files modified in the last 7 days
    
    std::cout << std::endl;
    displaySuccess("Found " + std::to_string(recentFiles.size()) + " recently modified files");
    
    for (const auto& file : recentFiles) {
        std::cout << YELLOW << "  " << file.path << RESET << std::endl;
        
        // Convert time_t to string
        auto modTime = std::localtime(&file.lastModified);
        char timeBuffer[80];
        std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", modTime);
        
        std::cout << "    Modified: " << CYAN << timeBuffer << RESET 
                << ", Owner: " << CYAN << file.owner << RESET 
                << ", Permissions: " << CYAN << file.permissions << RESET << std::endl;
        std::cout << std::endl;
    }
    
    // Cron Job Analysis
    displaySectionHeader("CRON JOB ANALYSIS");
    displayProgress("Analyzing cron jobs");
    auto cronJobs = CronAnalysis::analyzeCronJobs();
    CronAnalysis::displayCronJobs(cronJobs);
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Kernel Vulnerability Scan
    displaySectionHeader("KERNEL VULNERABILITY SCAN");
    displayProgress("Scanning for kernel vulnerabilities");
    KernelVulnScan::scanKernelVulnerabilities();
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Sudo Configuration Analysis
    displaySectionHeader("SUDO CONFIGURATION ANALYSIS");
    displayProgress("Analyzing sudo configuration");
    SudoAnalysis::displaySudoRules();
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Container Environment Analysis
    displaySectionHeader("CONTAINER ENVIRONMENT ANALYSIS");
    displayProgress("Detecting container environment");
    
    auto containerInfo = ContainerAnalysis::detectContainerEnvironment();
    
    if (containerInfo.type != ContainerAnalysis::ContainerType::NONE) {
        displaySuccess("Running in container environment");
        std::cout << BLUE << "  [*] " << RESET << "Container Type: " 
                  << CYAN << ContainerAnalysis::containerTypeToString(containerInfo.type) << RESET << std::endl;
        
        if (!containerInfo.name.empty()) {
            std::cout << BLUE << "  [*] " << RESET << "Container Name: " 
                      << CYAN << containerInfo.name << RESET << std::endl;
        }
        
        if (!containerInfo.id.empty()) {
            std::cout << BLUE << "  [*] " << RESET << "Container ID: " 
                      << CYAN << containerInfo.id << RESET << std::endl;
        }
        
        if (!containerInfo.image.empty()) {
            std::cout << BLUE << "  [*] " << RESET << "Container Image: " 
                      << CYAN << containerInfo.image << RESET << std::endl;
        }
        
        ContainerAnalysis::analyzeContainerEscapeVectors(containerInfo);
    } else {
        displaySuccess("Not running in a container environment");
    }
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Network Reconnaissance
    displaySectionHeader("NETWORK RECONNAISSANCE");
    displayProgress("Performing network reconnaissance");
    NetworkAnalysis::performNetworkRecon();
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // CVE Vulnerability Scan
    displaySectionHeader("CVE VULNERABILITY SCAN");
    displayProgress("Scanning for CVE-2025-32462 and CVE-2025-32463");
    CVEAnalysis::displayCVEInfo(CVEAnalysis::checkAllCVEs());
    
    // Sleep for a moment to let the user see the output
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Advanced System Checks
    runAdvancedSystemChecks();
    
    // Summary
    displaySectionHeader("SCAN SUMMARY");
    std::cout << BOLD << GREEN << "[" << getCurrentTimestamp() << "] " 
              << "LivingOfTheLand Toolkit scan completed." << RESET << std::endl;
    std::cout << std::endl;
    std::cout << BOLD << "Check the output above for potential security issues." << RESET << std::endl;
    std::cout << std::endl;
}

// Function to check for command line arguments
void parseCommandLineArgs(int argc, char* argv[]) {
    // Check for command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            std::cout << BOLD << "Usage: " << RESET << "./lotl [OPTIONS]" << std::endl;
            std::cout << std::endl;
            std::cout << BOLD << "Options:" << RESET << std::endl;
            std::cout << "  -h, --help     Show this help message" << std::endl;
            std::cout << "  -v, --version  Show version information" << std::endl;
            std::cout << std::endl;
            exit(0);
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "LivingOfTheLand Toolkit v2.0" << std::endl;
            exit(0);
        }
    }
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    parseCommandLineArgs(argc, argv);
    
    // Run all checks automatically
    runAllChecks();

    return 0;
}
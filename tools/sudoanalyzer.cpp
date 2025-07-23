#include "sudoanalyzer.h"
#include "executils.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <filesystem>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace SudoAnalysis {

bool isExploitableSudoRule(const std::string& command) {
    // List of potentially exploitable commands when run with sudo
    std::vector<std::string> exploitableCmds = {
        "ALL", "all", 
        "vi", "vim", "nano", "emacs", "pico", "joe", 
        "less", "more", "man", "view",
        "find", "bash", "sh", "ksh", "zsh", "csh", "tcsh", 
        "python", "python2", "python3", "perl", "ruby", "php", 
        "nmap", "nc", "netcat", "socat",
        "awk", "sed", "ed", "gdb", "strace", "ltrace",
        "mount", "umount", "fdisk", "parted",
        "dd", "cp", "mv", "ln", "chown", "chmod",
        "tar", "zip", "unzip", "7z", "gzip", "bzip2",
        "apt", "apt-get", "yum", "dnf", "pacman", "brew",
        "docker", "podman", "lxc", "systemctl", "service"
    };
    
    for (const auto& cmd : exploitableCmds) {
        // Check if the command is exactly the exploitable command or starts with it followed by a space
        if (command == cmd || 
            command.find(cmd + " ") == 0 ||
            command.find("/" + cmd) != std::string::npos) {
            return true;
        }
    }
    
    // Check for wildcard patterns or path traversal
    if (command.find('*') != std::string::npos || 
        command.find("../") != std::string::npos) {
        return true;
    }
    
    return false;
}

std::vector<SudoRule> analyzeSudoRules() {
    std::vector<SudoRule> rules;
    
    // Get current user
    std::string currentUser = ExecUtils::execCommand("whoami");
    currentUser.erase(std::remove(currentUser.begin(), currentUser.end(), '\n'), currentUser.end());
    
    // Detect operating system
    std::string osType = ExecUtils::execCommand("uname -s");
    osType.erase(std::remove(osType.begin(), osType.end(), '\n'), osType.end());
    
    // Try to list sudo rules without password prompt
    std::string sudoOutput;
    if (osType == "Darwin") {
        // macOS - try without sudo first
        sudoOutput = ExecUtils::execCommand("sudo -n -l 2>/dev/null");
    } else {
        // Linux - try without sudo first
        sudoOutput = ExecUtils::execCommand("sudo -n -l 2>/dev/null");
    }
    
    if (sudoOutput.empty()) {
        std::cout << YELLOW << "  [*] Unable to list sudo rules (password required or no sudo access)" << RESET << std::endl;
        
        // Try to read sudoers file directly
        std::string sudoersContent = ExecUtils::execCommand("cat /etc/sudoers 2>/dev/null");
        if (sudoersContent.empty()) {
            std::cout << YELLOW << "  [*] Unable to read /etc/sudoers file" << RESET << std::endl;
            
            // Try to read sudoers.d directory
            if (std::filesystem::exists("/etc/sudoers.d")) {
                std::cout << BLUE << "  [*] " << RESET << "Checking /etc/sudoers.d directory" << std::endl;
                
                try {
                    for (const auto& entry : std::filesystem::directory_iterator("/etc/sudoers.d")) {
                        if (std::filesystem::is_regular_file(entry.path())) {
                            std::string filePath = entry.path().string();
                            std::string fileContent = ExecUtils::execCommand("cat \"" + filePath + "\" 2>/dev/null");
                            
                            if (!fileContent.empty()) {
                                std::istringstream stream(fileContent);
                                std::string line;
                                
                                while (std::getline(stream, line)) {
                                    if (line.empty() || line[0] == '#') continue;
                                    
                                    // Basic parsing (would need more sophisticated parsing in production)
                                    if (line.find("ALL") != std::string::npos) {
                                        SudoRule rule;
                                        
                                        // Extract user
                                        size_t userEnd = line.find_first_of(" \t");
                                        if (userEnd != std::string::npos) {
                                            rule.user = line.substr(0, userEnd);
                                            
                                            // Extract host and command
                                            std::regex ruleRegex("([^=]*)=\\(([^)]*)\\)\\s*(.*)");
                                            std::smatch matches;
                                            
                                            if (std::regex_search(line, matches, ruleRegex) && matches.size() > 3) {
                                                rule.host = matches[1].str();
                                                rule.asUser = matches[2].str();
                                                rule.command = matches[3].str();
                                                
                                                rule.noPassword = (line.find("NOPASSWD") != std::string::npos);
                                                rule.isExploitable = isExploitableSudoRule(rule.command);
                                                
                                                rules.push_back(rule);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (const std::filesystem::filesystem_error& e) {
                    // Skip directories that can't be accessed
                }
            }
            
            return rules;
        }
        
        // Parse sudoers file
        std::istringstream stream(sudoersContent);
        std::string line;
        
        while (std::getline(stream, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            // Basic parsing (would need more sophisticated parsing in production)
            if (line.find("ALL") != std::string::npos) {
                SudoRule rule;
                
                // Extract user
                size_t userEnd = line.find_first_of(" \t");
                if (userEnd != std::string::npos) {
                    rule.user = line.substr(0, userEnd);
                    
                    // Extract host and command
                    std::regex ruleRegex("([^=]*)=\\(([^)]*)\\)\\s*(.*)");
                    std::smatch matches;
                    
                    if (std::regex_search(line, matches, ruleRegex) && matches.size() > 3) {
                        rule.host = matches[1].str();
                        rule.asUser = matches[2].str();
                        rule.command = matches[3].str();
                        
                        rule.noPassword = (line.find("NOPASSWD") != std::string::npos);
                        rule.isExploitable = isExploitableSudoRule(rule.command);
                        
                        rules.push_back(rule);
                    }
                }
            }
        }
    } else {
        // Parse sudo -l output
        std::istringstream stream(sudoOutput);
        std::string line;
        bool inRules = false;
        
        while (std::getline(stream, line)) {
            if (line.find("may run the following commands") != std::string::npos) {
                inRules = true;
                continue;
            }
            
            if (inRules && !line.empty() && line[0] != ' ' && line[0] != '\t') {
                SudoRule rule;
                rule.user = currentUser;
                
                // Extract command
                size_t cmdStart = line.find_last_of(':');
                if (cmdStart != std::string::npos) {
                    rule.command = line.substr(cmdStart + 1);
                    rule.command.erase(0, rule.command.find_first_not_of(" \t"));
                    
                    // Extract user and host
                    size_t userStart = line.find('(');
                    size_t userEnd = line.find(')');
                    
                    if (userStart != std::string::npos && userEnd != std::string::npos) {
                        std::string userHost = line.substr(userStart + 1, userEnd - userStart - 1);
                        size_t colonPos = userHost.find(':');
                        
                        if (colonPos != std::string::npos) {
                            rule.asUser = userHost.substr(0, colonPos);
                            rule.host = userHost.substr(colonPos + 1);
                        } else {
                            rule.asUser = userHost;
                            rule.host = "ALL";
                        }
                    }
                    
                    rule.noPassword = (line.find("NOPASSWD") != std::string::npos);
                    rule.isExploitable = isExploitableSudoRule(rule.command);
                    
                    rules.push_back(rule);
                }
            }
        }
    }
    
    return rules;
}

void displaySudoRules() {
    std::cout << BOLD << "\n[+] Analyzing Sudo Configuration..." << RESET << std::endl;
    
    std::vector<SudoRule> rules = analyzeSudoRules();
    
    if (rules.empty()) {
        std::cout << YELLOW << "  [*] No sudo rules found or unable to access them" << RESET << std::endl;
        return;
    }
    
    std::cout << BOLD << "\n  [*] Found " << rules.size() << " sudo rules:" << RESET << std::endl;
    
    int exploitableCount = 0;
    for (const auto& rule : rules) {
        std::cout << BLUE << "  [*] " << RESET << "User: " << CYAN << rule.user << RESET 
                  << " on " << MAGENTA << rule.host << RESET
                  << " as " << GREEN << rule.asUser << RESET 
                  << " can run: " << YELLOW << rule.command << RESET;
        
        if (rule.noPassword) {
            std::cout << " " << RED << "(NO PASSWORD REQUIRED)" << RESET;
        }
        
        std::cout << std::endl;
        
        if (rule.isExploitable) {
            exploitableCount++;
            std::cout << RED << "      [!] This rule is potentially exploitable for privilege escalation!" << RESET << std::endl;
            
            // Provide exploitation hints based on the command
            if (rule.command.find("vi") != std::string::npos || 
                rule.command.find("vim") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: In vim, type ':!sh' to get a shell" << RESET << std::endl;
            } else if (rule.command.find("find") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: 'sudo find . -exec /bin/sh \\;'" << RESET << std::endl;
            } else if (rule.command.find("man") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: In man, type '!sh' to get a shell" << RESET << std::endl;
            } else if (rule.command.find("less") != std::string::npos || 
                      rule.command.find("more") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: In less/more, type '!sh' to get a shell" << RESET << std::endl;
            } else if (rule.command.find("nmap") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: 'sudo nmap --interactive' then '!sh'" << RESET << std::endl;
            } else if (rule.command.find("python") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: 'sudo python -c \"import os; os.system('/bin/bash')\"'" << RESET << std::endl;
            } else if (rule.command.find("ALL") != std::string::npos) {
                std::cout << YELLOW << "      [+] Exploitation hint: User can run ANY command as " << rule.asUser << RESET << std::endl;
            }
        }
        
        std::cout << std::endl;
    }
    
    if (exploitableCount > 0) {
        std::cout << BOLD << RED << "  [!] Found " << exploitableCount << " potentially exploitable sudo rules!" << RESET << std::endl;
    } else {
        std::cout << BOLD << GREEN << "  [✓] No obviously exploitable sudo rules found." << RESET << std::endl;
    }
}

} // namespace SudoAnalysis
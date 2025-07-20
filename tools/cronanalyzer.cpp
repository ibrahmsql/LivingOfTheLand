#include "cronanalyzer.h"
#include "executils.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <regex>
#include <vector>
#include <unistd.h> // W_OK tanımı için eklendi

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace CronAnalysis {

bool isExploitableCronJob(const CronJob& job) {
    // Check if the cron job is writable
    if (job.isWritable) {
        return true;
    }
    
    // Check if the command uses a writable script or binary
    std::string cmd = job.command;
    std::istringstream iss(cmd);
    std::string firstToken;
    iss >> firstToken;
    
    // Remove any parameters
    size_t spacePos = firstToken.find(' ');
    if (spacePos != std::string::npos) {
        firstToken = firstToken.substr(0, spacePos);
    }
    
    // Check if the command is a path to a file
    if (firstToken.find('/') != std::string::npos) {
        // Check if the file is writable by current user
        if (access(firstToken.c_str(), W_OK) == 0) {
            return true;
        }
        
        // Check if any directory in the path is writable
        std::string path = firstToken;
        while (path.find('/') != std::string::npos) {
            path = path.substr(0, path.find_last_of('/'));
            if (!path.empty() && access(path.c_str(), W_OK) == 0) {
                return true;
            }
        }
    }
    
    // Check for wildcards or path traversal
    if (cmd.find('*') != std::string::npos || 
        cmd.find("../") != std::string::npos) {
        return true;
    }
    
    // Check for common exploitable commands
    std::vector<std::string> exploitableCmds = {
        "bash", "sh", "python", "perl", "ruby", "php", "nc", "netcat",
        "wget", "curl", "tar", "find", "cp", "mv", "ln"
    };
    
    for (const auto& exploitableCmd : exploitableCmds) {
        if (cmd.find(exploitableCmd) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::vector<CronJob> analyzeCronJobs() {
    std::vector<CronJob> cronJobs;
    
    // System-wide crontabs
    std::vector<std::string> cronPaths = {
        "/etc/crontab", 
        "/etc/cron.d", 
        "/var/spool/cron", 
        "/var/spool/cron/crontabs", 
        "/etc/anacrontab",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly"
    };
    
    for (const auto& path : cronPaths) {
        if (std::filesystem::exists(path)) {
            if (std::filesystem::is_directory(path)) {
                try {
                    for (const auto& entry : std::filesystem::directory_iterator(path)) {
                        std::string filePath = entry.path().string();
                        // Skip if not regular file
                        if (!std::filesystem::is_regular_file(entry.path())) {
                            continue;
                        }
                        
                        std::string content = ExecUtils::execCommand("cat \"" + filePath + "\" 2>/dev/null");
                        
                        // Parse cron content
                        std::istringstream stream(content);
                        std::string line;
                        
                        while (std::getline(stream, line)) {
                            if (line.empty() || line[0] == '#') continue;
                            
                            CronJob job;
                            job.source = filePath;
                            job.isWritable = (access(filePath.c_str(), W_OK) == 0);
                            
                            // Basic parsing (would need more sophisticated parsing in production)
                            std::istringstream lineStream(line);
                            std::string token;
                            std::vector<std::string> tokens;
                            
                            while (lineStream >> token) {
                                tokens.push_back(token);
                            }
                            
                            if (tokens.size() >= 7) {
                                job.schedule = tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + 
                                              tokens[3] + " " + tokens[4];
                                job.user = tokens[5];
                                job.command = tokens[6];
                                for (size_t i = 7; i < tokens.size(); ++i) {
                                    job.command += " " + tokens[i];
                                }
                                cronJobs.push_back(job);
                            }
                        }
                    }
                } catch (const std::filesystem::filesystem_error& e) {
                    // Skip directories that can't be accessed
                    continue;
                }
            } else {
                std::string content = ExecUtils::execCommand("cat \"" + path + "\" 2>/dev/null");
                
                // Parse cron content
                std::istringstream stream(content);
                std::string line;
                
                while (std::getline(stream, line)) {
                    if (line.empty() || line[0] == '#') continue;
                    
                    CronJob job;
                    job.source = path;
                    job.isWritable = (access(path.c_str(), W_OK) == 0);
                    
                    // Basic parsing
                    std::istringstream lineStream(line);
                    std::string token;
                    std::vector<std::string> tokens;
                    
                    while (lineStream >> token) {
                        tokens.push_back(token);
                    }
                    
                    if (tokens.size() >= 6) {
                        job.schedule = tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + 
                                      tokens[3] + " " + tokens[4];
                        job.user = tokens[5];
                        if (tokens.size() > 6) {
                            job.command = tokens[6];
                            for (size_t i = 7; i < tokens.size(); ++i) {
                                job.command += " " + tokens[i];
                            }
                        }
                        cronJobs.push_back(job);
                    }
                }
            }
        }
    }
    
    // User crontabs
    std::string userList = ExecUtils::execCommand("cut -d: -f1 /etc/passwd");
    std::istringstream userStream(userList);
    std::string user;
    
    while (std::getline(userStream, user)) {
        if (user.empty()) continue;
        
        std::string userCron = ExecUtils::execCommand("crontab -l -u " + user + " 2>/dev/null");
        
        if (!userCron.empty()) {
            std::istringstream cronStream(userCron);
            std::string line;
            
            while (std::getline(cronStream, line)) {
                if (line.empty() || line[0] == '#') continue;
                
                CronJob job;
                job.user = user;
                job.source = "User crontab for " + user;
                job.isWritable = false; // Would need to check permissions
                
                // Basic parsing
                std::istringstream lineStream(line);
                std::string token;
                std::vector<std::string> tokens;
                
                while (lineStream >> token) {
                    tokens.push_back(token);
                }
                
                if (tokens.size() >= 5) {
                    job.schedule = tokens[0] + " " + tokens[1] + " " + tokens[2] + " " + 
                                  tokens[3] + " " + tokens[4];
                    if (tokens.size() > 5) {
                        job.command = tokens[5];
                        for (size_t i = 6; i < tokens.size(); ++i) {
                            job.command += " " + tokens[i];
                        }
                    }
                    cronJobs.push_back(job);
                }
            }
        }
    }
    
    return cronJobs;
}

void displayCronJobs(const std::vector<CronJob>& jobs) {
    std::cout << BOLD << "\n[+] Found " << jobs.size() << " cron jobs:" << RESET << std::endl;
    
    for (const auto& job : jobs) {
        std::cout << BLUE << "  [*] " << RESET << "User: " << CYAN << job.user << RESET << 
                  ", Schedule: " << YELLOW << job.schedule << RESET << std::endl;
        std::cout << "      Command: " << GREEN << job.command << RESET << std::endl;
        std::cout << "      Source: " << job.source;
        
        if (job.isWritable) {
            std::cout << " " << RED << "(WRITABLE)" << RESET;
        }
        
        std::cout << std::endl;
        
        if (isExploitableCronJob(job)) {
            std::cout << RED << "      [!] This cron job is potentially exploitable!" << RESET << std::endl;
        }
        
        std::cout << std::endl;
    }
}

} // namespace CronAnalysis 
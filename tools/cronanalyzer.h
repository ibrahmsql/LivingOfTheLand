#pragma once

#include <vector>
#include <string>
#include <filesystem>

namespace CronAnalysis {
    struct CronJob {
        std::string user;
        std::string schedule;
        std::string command;
        std::string source;
        bool isWritable;
    };

    // Analyze all cron jobs in the system
    std::vector<CronJob> analyzeCronJobs();
    
    // Display cron job analysis results
    void displayCronJobs(const std::vector<CronJob>& jobs);
    
    // Check if a cron job is potentially exploitable
    bool isExploitableCronJob(const CronJob& job);
} 
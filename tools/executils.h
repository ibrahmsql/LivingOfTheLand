#pragma once
#include <string>
#include <vector>
#include <optional>

namespace ExecUtils {
    // Check if a command exists in the system
    // Returns: 1 if exists, 0 if not exists, -1 if error
int commandExists(const std::string& cmd);
    
    // Execute a command and return its output as string
    // Returns: Command output or error message
std::string execCommand(const std::string& cmd);
    
    // Execute a command with timeout
    // Returns: Command output or empty string if timeout
    std::string execCommandWithTimeout(const std::string& cmd, int timeout_seconds);
    
    // Execute a command and return output as vector of lines
    std::vector<std::string> execCommandGetLines(const std::string& cmd);
    
    // Execute a command with sudo if available
    // Returns: Command output or error message
    std::string execSudoCommand(const std::string& cmd, bool askPassword = false);
    
    // Execute a command in background
    // Returns: Process ID or -1 if failed
    int execCommandBackground(const std::string& cmd);
    
    // Check if a process is running
    // Returns: true if running, false if not
    bool isProcessRunning(const std::string& processName);
    
    // Kill a process by name
    // Returns: true if killed, false if failed
    bool killProcess(const std::string& processName);
    
    // Get environment variable value
    // Returns: Value or empty optional if not found
    std::optional<std::string> getEnvVar(const std::string& name);
    
    // Set environment variable
    // Returns: true if success, false if failed
    bool setEnvVar(const std::string& name, const std::string& value);
}
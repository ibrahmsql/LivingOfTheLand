#include "executils.h"
#include <cstdlib>
#include <array>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"

namespace ExecUtils {

int commandExists(const std::string& cmd) {
    try {
    std::string check = "command -v " + cmd + " >/dev/null 2>&1";
        int result = std::system(check.c_str());
        if (result == 0) {
            return 1; // Command exists
        } else {
            return 0; // Command does not exist
        }
    } catch (const std::exception& e) {
        std::cerr << RED << "Error checking command: " << e.what() << RESET << std::endl;
        return -1; // Error occurred
    }
}

std::string execCommand(const std::string& cmd) {
    std::array<char, 4096> buffer;
    std::string result;

    try {
    FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("popen() failed");
        }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

        int status = pclose(pipe);
        if (status == -1) {
            throw std::runtime_error("pclose() failed");
        }

        return result;
    } catch (const std::exception& e) {
        return "ERROR: " + std::string(e.what());
    }
}

std::string execCommandWithTimeout(const std::string& cmd, int timeout_seconds) {
    // Create pipes for communication
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return "ERROR: Failed to create pipe";
    }
    
    // Fork process
    pid_t pid = fork();
    
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "ERROR: Fork failed";
    }
    
    if (pid == 0) {
        // Child process
        close(pipefd[0]); // Close read end
        
        // Redirect stdout to pipe
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        // Execute command
        execl("/bin/sh", "sh", "-c", cmd.c_str(), NULL);
        exit(EXIT_FAILURE); // Only reached if execl fails
    }
    
    // Parent process
    close(pipefd[1]); // Close write end
    
    // Read from pipe
    std::string result;
    char buffer[4096];
    ssize_t bytes_read;
    
    // Set non-blocking
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    
    // Wait with timeout
    time_t start_time = time(NULL);
    bool timeout_occurred = false;
    int status;
    pid_t wait_result;
    
    while (true) {
        wait_result = waitpid(pid, &status, WNOHANG);
        
        if (wait_result == pid) {
            // Process finished
            break;
        }
        
        if (wait_result == -1) {
            // Error occurred
            close(pipefd[0]);
            return "ERROR: waitpid failed";
        }
        
        // Check for timeout
        if (difftime(time(NULL), start_time) > timeout_seconds) {
            kill(pid, SIGTERM);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            kill(pid, SIGKILL);
            timeout_occurred = true;
            break;
        }
        
        // Try to read
        bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            result += buffer;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Read any remaining data
    while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        result += buffer;
    }
    
    close(pipefd[0]);
    
    if (timeout_occurred) {
        return "ERROR: Command timed out after " + std::to_string(timeout_seconds) + " seconds";
    }
    
    return result;
}

std::vector<std::string> execCommandGetLines(const std::string& cmd) {
    std::vector<std::string> lines;
    std::string output = execCommand(cmd);
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    
    return lines;
}

std::string execSudoCommand(const std::string& cmd, bool askPassword) {
    std::string sudoCmd;
    
    if (askPassword) {
        sudoCmd = "sudo " + cmd;
    } else {
        sudoCmd = "sudo -n " + cmd + " 2>/dev/null";
    }
    
    return execCommand(sudoCmd);
}

int execCommandBackground(const std::string& cmd) {
    std::string fullCmd = cmd + " >/dev/null 2>&1 & echo $!";
    std::string pidStr = execCommand(fullCmd);
    
    try {
        return std::stoi(pidStr);
    } catch (const std::exception& e) {
        return -1;
    }
}

bool isProcessRunning(const std::string& processName) {
    std::string cmd = "pgrep -x \"" + processName + "\" >/dev/null";
    return std::system(cmd.c_str()) == 0;
}

bool killProcess(const std::string& processName) {
    std::string cmd = "pkill -x \"" + processName + "\"";
    return std::system(cmd.c_str()) == 0;
}

std::optional<std::string> getEnvVar(const std::string& name) {
    const char* value = std::getenv(name.c_str());
    if (value) {
        return std::string(value);
    }
    return std::nullopt;
}

bool setEnvVar(const std::string& name, const std::string& value) {
    return setenv(name.c_str(), value.c_str(), 1) == 0;
}

} // namespace ExecUtils
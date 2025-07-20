#include "networkanalyzer.h"
#include "executils.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <vector>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

namespace NetworkAnalysis {

// Helper function to trim whitespace
std::string trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), [](int c) { return std::isspace(c); });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](int c) { return std::isspace(c); }).base();
    
    return (start < end) ? std::string(start, end) : std::string();
}

// Get all network interfaces
std::vector<NetworkInterface> getNetworkInterfaces() {
    std::vector<NetworkInterface> interfaces;
    
    // Get interface information using ip command
    std::string ipOutput = ExecUtils::execCommand("ip -o addr show 2>/dev/null");
    if (ipOutput.empty()) {
        // Fallback to ifconfig if ip command not available
        ipOutput = ExecUtils::execCommand("ifconfig 2>/dev/null");
    }
    
    std::istringstream stream(ipOutput);
    std::string line;
    NetworkInterface currentIf;
    
    std::regex ipRegex("inet\\s+([0-9.]+)");
    std::regex macRegex("([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})");
    
    while (std::getline(stream, line)) {
        // Extract interface name
        std::regex ifaceRegex("^\\d+:\\s+([^:]+):");
        std::smatch ifaceMatch;
        
        if (std::regex_search(line, ifaceMatch, ifaceRegex)) {
            if (!currentIf.name.empty()) {
                interfaces.push_back(currentIf);
            }
            
            currentIf = NetworkInterface();
            currentIf.name = ifaceMatch[1].str();
            currentIf.isLoopback = (currentIf.name == "lo");
            currentIf.isUp = (line.find("UP") != std::string::npos);
        }
        
        // Extract IP address
        std::smatch ipMatch;
        if (std::regex_search(line, ipMatch, ipRegex)) {
            currentIf.ipAddress = ipMatch[1].str();
        }
        
        // Extract MAC address
        std::smatch macMatch;
        if (std::regex_search(line, macMatch, macRegex)) {
            currentIf.macAddress = macMatch[1].str();
        }
    }
    
    // Add the last interface
    if (!currentIf.name.empty()) {
        interfaces.push_back(currentIf);
    }
    
    return interfaces;
}

// Get all active network connections
std::vector<NetworkConnection> getActiveConnections() {
    std::vector<NetworkConnection> connections;
    
    // Try using ss command first (more modern)
    std::string ssOutput = ExecUtils::execCommand("ss -tunapl 2>/dev/null");
    bool useSS = !ssOutput.empty();
    
    std::string netstatOutput;
    if (!useSS) {
        // Fallback to netstat if ss not available
        netstatOutput = ExecUtils::execCommand("netstat -tunapl 2>/dev/null");
        if (netstatOutput.empty()) {
            return connections;
        }
    }
    
    std::string& output = useSS ? ssOutput : netstatOutput;
    std::istringstream stream(output);
    std::string line;
    
    // Skip header line(s)
    std::getline(stream, line);
    if (!useSS) {
        std::getline(stream, line); // netstat has an extra header line
    }
    
    while (std::getline(stream, line)) {
        NetworkConnection conn;
        std::istringstream lineStream(line);
        std::string proto, localAddr, remoteAddr, state, processInfo;
        
        if (useSS) {
            // Parse ss output
            lineStream >> proto >> state;
            lineStream >> localAddr >> remoteAddr;
            
            // Get the rest of the line for process info
            std::getline(lineStream, processInfo);
        } else {
            // Parse netstat output
            lineStream >> proto >> localAddr >> remoteAddr >> state;
            
            // Get the rest of the line for process info
            std::getline(lineStream, processInfo);
        }
        
        conn.protocol = proto;
        
        // Parse local address and port
        size_t colonPos = localAddr.find_last_of(':');
        if (colonPos != std::string::npos) {
            conn.localAddress = localAddr.substr(0, colonPos);
            try {
                conn.localPort = std::stoi(localAddr.substr(colonPos + 1));
            } catch (...) {
                conn.localPort = 0;
            }
        }
        
        // Parse remote address and port
        colonPos = remoteAddr.find_last_of(':');
        if (colonPos != std::string::npos) {
            conn.remoteAddress = remoteAddr.substr(0, colonPos);
            try {
                conn.remotePort = std::stoi(remoteAddr.substr(colonPos + 1));
            } catch (...) {
                conn.remotePort = 0;
            }
        }
        
        conn.state = state;
        
        // Extract PID and process name
        std::regex pidRegex("pid=(\\d+)");
        std::regex cmdRegex("users:\\(\\(\"([^\"]+)\"");
        
        std::smatch pidMatch, cmdMatch;
        if (std::regex_search(processInfo, pidMatch, pidRegex)) {
            try {
                conn.pid = std::stoi(pidMatch[1].str());
            } catch (...) {
                conn.pid = 0;
            }
        }
        
        if (std::regex_search(processInfo, cmdMatch, cmdRegex)) {
            conn.processName = cmdMatch[1].str();
        }
        
        connections.push_back(conn);
    }
    
    return connections;
}

// Scan ports on local or remote host
std::vector<PortScanResult> scanPorts(const std::string& host, const std::vector<int>& ports) {
    std::vector<PortScanResult> results;
    std::mutex resultsMutex;
    std::atomic<int> completedScans(0);
    int totalPorts = ports.size();
    
    // Function to scan a single port
    auto scanPort = [&](const std::string& host, int port) {
        PortScanResult result;
        result.host = host;
        result.port = port;
        result.isOpen = false;
        
        // Try using nc (netcat) for port scanning
        std::string cmd = "nc -z -w1 " + host + " " + std::to_string(port) + " 2>/dev/null";
        int exitCode = std::system((cmd + " >/dev/null").c_str());
        
        if (exitCode == 0) {
            result.isOpen = true;
            
            // Try to determine service name
            std::string serviceCmd = "grep -w " + std::to_string(port) + " /etc/services 2>/dev/null | head -1";
            std::string serviceOutput = ExecUtils::execCommand(serviceCmd);
            
            if (!serviceOutput.empty()) {
                std::istringstream serviceStream(serviceOutput);
                std::string serviceName;
                serviceStream >> serviceName;
                result.service = serviceName;
            } else {
                result.service = "unknown";
            }
        }
        
        // Update results
        {
            std::lock_guard<std::mutex> lock(resultsMutex);
            results.push_back(result);
        }
        
        // Update progress counter
        completedScans++;
    };
    
    // Create threads for scanning
    const int maxThreads = 20; // Limit number of concurrent threads
    std::vector<std::thread> threads;
    
    for (size_t i = 0; i < ports.size(); i += maxThreads) {
        // Clear previous threads
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        threads.clear();
        
        // Create new batch of threads
        size_t end = std::min(i + maxThreads, ports.size());
        for (size_t j = i; j < end; ++j) {
            threads.emplace_back(scanPort, host, ports[j]);
        }
        
        // Wait for current batch to complete
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }
    
    // Sort results by port number
    std::sort(results.begin(), results.end(), 
              [](const PortScanResult& a, const PortScanResult& b) {
                  return a.port < b.port;
              });
    
    return results;
}

// Get DNS information for a host
std::map<std::string, std::string> getDnsInfo(const std::string& host) {
    std::map<std::string, std::string> dnsInfo;
    
    // Forward lookup
    std::string cmd = "dig +short " + host + " 2>/dev/null";
    std::string output = ExecUtils::execCommand(cmd);
    
    if (!output.empty()) {
        std::istringstream stream(output);
        std::string ip;
        std::vector<std::string> ips;
        
        while (std::getline(stream, ip)) {
            ip = trim(ip);
            if (!ip.empty()) {
                ips.push_back(ip);
            }
        }
        
        if (!ips.empty()) {
            dnsInfo["ip"] = ips[0];
            
            // Reverse lookup
            cmd = "dig +short -x " + ips[0] + " 2>/dev/null";
            output = ExecUtils::execCommand(cmd);
            
            if (!output.empty()) {
                output = trim(output);
                // Remove trailing dot if present
                if (!output.empty() && output.back() == '.') {
                    output.pop_back();
                }
                dnsInfo["ptr"] = output;
            }
        }
    }
    
    // Try to get MX records
    cmd = "dig +short MX " + host + " 2>/dev/null";
    output = ExecUtils::execCommand(cmd);
    
    if (!output.empty()) {
        dnsInfo["mx"] = output;
    }
    
    // Try to get NS records
    cmd = "dig +short NS " + host + " 2>/dev/null";
    output = ExecUtils::execCommand(cmd);
    
    if (!output.empty()) {
        dnsInfo["ns"] = output;
    }
    
    return dnsInfo;
}

// Display network interfaces
void displayNetworkInterfaces() {
    std::cout << BOLD << "\n[+] Network Interfaces:" << RESET << std::endl;
    
    std::vector<NetworkInterface> interfaces = getNetworkInterfaces();
    
    if (interfaces.empty()) {
        std::cout << YELLOW << "  [*] No network interfaces found" << RESET << std::endl;
        return;
    }
    
    for (const auto& iface : interfaces) {
        std::cout << BLUE << "  [*] " << RESET << "Interface: " << CYAN << iface.name << RESET;
        
        if (iface.isUp) {
            std::cout << " " << GREEN << "(UP)" << RESET;
        } else {
            std::cout << " " << RED << "(DOWN)" << RESET;
        }
        
        if (iface.isLoopback) {
            std::cout << " " << YELLOW << "(LOOPBACK)" << RESET;
        }
        
        std::cout << std::endl;
        
        if (!iface.ipAddress.empty()) {
            std::cout << "      IP Address: " << YELLOW << iface.ipAddress << RESET << std::endl;
        }
        
        if (!iface.macAddress.empty()) {
            std::cout << "      MAC Address: " << YELLOW << iface.macAddress << RESET << std::endl;
        }
        
        std::cout << std::endl;
    }
}

// Display active connections
void displayActiveConnections() {
    std::cout << BOLD << "\n[+] Active Network Connections:" << RESET << std::endl;
    
    std::vector<NetworkConnection> connections = getActiveConnections();
    
    if (connections.empty()) {
        std::cout << YELLOW << "  [*] No active connections found" << RESET << std::endl;
        return;
    }
    
    // Filter for listening and established connections
    std::vector<NetworkConnection> listeningConns;
    std::vector<NetworkConnection> establishedConns;
    
    for (const auto& conn : connections) {
        if (conn.state == "LISTEN" || conn.state == "LISTENING") {
            listeningConns.push_back(conn);
        } else if (conn.state == "ESTABLISHED") {
            establishedConns.push_back(conn);
        }
    }
    
    // Display listening connections
    std::cout << BLUE << "  [*] " << RESET << "Listening Ports:" << std::endl;
    
    if (listeningConns.empty()) {
        std::cout << YELLOW << "      No listening ports found" << RESET << std::endl;
    } else {
        for (const auto& conn : listeningConns) {
            std::cout << "      " << YELLOW << conn.protocol << RESET 
                      << " " << CYAN << conn.localAddress << ":" << conn.localPort << RESET;
            
            if (!conn.processName.empty()) {
                std::cout << " - " << GREEN << conn.processName << RESET;
                if (conn.pid > 0) {
                    std::cout << " (PID: " << conn.pid << ")";
                }
            }
            
            std::cout << std::endl;
        }
    }
    
    std::cout << std::endl;
    
    // Display established connections
    std::cout << BLUE << "  [*] " << RESET << "Established Connections:" << std::endl;
    
    if (establishedConns.empty()) {
        std::cout << YELLOW << "      No established connections found" << RESET << std::endl;
    } else {
        for (const auto& conn : establishedConns) {
            std::cout << "      " << YELLOW << conn.protocol << RESET 
                      << " " << CYAN << conn.localAddress << ":" << conn.localPort << RESET
                      << " -> " << MAGENTA << conn.remoteAddress << ":" << conn.remotePort << RESET;
            
            if (!conn.processName.empty()) {
                std::cout << " - " << GREEN << conn.processName << RESET;
                if (conn.pid > 0) {
                    std::cout << " (PID: " << conn.pid << ")";
                }
            }
            
            std::cout << std::endl;
        }
    }
}

// Perform basic network reconnaissance
void performNetworkRecon() {
    std::cout << BOLD << "\n[+] Performing Network Reconnaissance..." << RESET << std::endl;
    
    // Get local IP and gateway
    std::string localIP = ExecUtils::execCommand("hostname -I | awk '{print $1}' 2>/dev/null");
    localIP = trim(localIP);
    
    std::string gateway = ExecUtils::execCommand("ip route | grep default | awk '{print $3}' 2>/dev/null");
    gateway = trim(gateway);
    
    std::cout << BLUE << "  [*] " << RESET << "Local IP: " << CYAN << localIP << RESET << std::endl;
    std::cout << BLUE << "  [*] " << RESET << "Default Gateway: " << CYAN << gateway << RESET << std::endl;
    
    // Get public IP
    std::string publicIP = ExecUtils::execCommand("curl -s ifconfig.me 2>/dev/null");
    if (!publicIP.empty()) {
        std::cout << BLUE << "  [*] " << RESET << "Public IP: " << CYAN << publicIP << RESET << std::endl;
    }
    
    // Display network interfaces
    displayNetworkInterfaces();
    
    // Display active connections
    displayActiveConnections();
    
    // Scan common ports on localhost
    std::cout << BOLD << "\n[+] Scanning Common Ports on Localhost..." << RESET << std::endl;
    
    std::vector<int> commonPorts = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                                   443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 
                                   5900, 5901, 6000, 8080, 8443};
    
    std::vector<PortScanResult> results = scanPorts("127.0.0.1", commonPorts);
    
    bool foundOpenPorts = false;
    for (const auto& result : results) {
        if (result.isOpen) {
            if (!foundOpenPorts) {
                std::cout << BLUE << "  [*] " << RESET << "Open Ports:" << std::endl;
                foundOpenPorts = true;
            }
            
            std::cout << "      " << CYAN << result.port << RESET << "/tcp - " 
                      << GREEN << result.service << RESET << std::endl;
        }
    }
    
    if (!foundOpenPorts) {
        std::cout << YELLOW << "  [*] No open ports found on localhost" << RESET << std::endl;
    }
    
    // Try to get DNS server information
    std::cout << BOLD << "\n[+] DNS Server Information:" << RESET << std::endl;
    
    std::string dnsServers = ExecUtils::execCommand("cat /etc/resolv.conf | grep nameserver | awk '{print $2}' 2>/dev/null");
    
    if (!dnsServers.empty()) {
        std::istringstream dnsStream(dnsServers);
        std::string dnsServer;
        
        while (std::getline(dnsStream, dnsServer)) {
            dnsServer = trim(dnsServer);
            if (!dnsServer.empty()) {
                std::cout << BLUE << "  [*] " << RESET << "DNS Server: " << CYAN << dnsServer << RESET << std::endl;
            }
        }
    } else {
        std::cout << YELLOW << "  [*] No DNS servers found" << RESET << std::endl;
    }
    
    // Try to get hostname information
    std::string hostname = ExecUtils::execCommand("hostname -f 2>/dev/null");
    hostname = trim(hostname);
    
    if (!hostname.empty()) {
        std::cout << BLUE << "  [*] " << RESET << "Hostname: " << CYAN << hostname << RESET << std::endl;
        
        // Try to get DNS information for hostname
        std::map<std::string, std::string> dnsInfo = getDnsInfo(hostname);
        
        if (!dnsInfo.empty()) {
            std::cout << BLUE << "  [*] " << RESET << "DNS Information for " << CYAN << hostname << RESET << ":" << std::endl;
            
            for (const auto& [key, value] : dnsInfo) {
                std::cout << "      " << YELLOW << key << RESET << ": " << value << std::endl;
            }
        }
    }
}

} // namespace NetworkAnalysis 
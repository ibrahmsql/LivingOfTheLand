#pragma once

#include <string>
#include <vector>
#include <map>

namespace NetworkAnalysis {
    struct NetworkInterface {
        std::string name;
        std::string ipAddress;
        std::string macAddress;
        bool isUp;
        bool isLoopback;
    };
    
    struct NetworkConnection {
        std::string protocol;
        std::string localAddress;
        int localPort;
        std::string remoteAddress;
        int remotePort;
        std::string state;
        std::string processName;
        int pid;
    };
    
    struct PortScanResult {
        std::string host;
        int port;
        bool isOpen;
        std::string service;
    };
    
    // Get all network interfaces
    std::vector<NetworkInterface> getNetworkInterfaces();
    
    // Get all active network connections
    std::vector<NetworkConnection> getActiveConnections();
    
    // Scan ports on local or remote host
    std::vector<PortScanResult> scanPorts(const std::string& host, const std::vector<int>& ports);
    
    // Get DNS information for a host
    std::map<std::string, std::string> getDnsInfo(const std::string& host);
    
    // Display network interfaces
    void displayNetworkInterfaces();
    
    // Display active connections
    void displayActiveConnections();
    
    // Perform basic network reconnaissance
    void performNetworkRecon();
} 
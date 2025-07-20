#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>

namespace WebUtils {
    // Response structure for HTTP requests
    struct HttpResponse {
        int statusCode;
        std::map<std::string, std::string> headers;
        std::vector<unsigned char> body;
        std::string error;
        bool success;
    };

    // Download a file from URL and save to disk
    // Returns: Vector containing file content and success status
    HttpResponse downloadFile(const std::string& url, const std::string& filename);

    // Download a file from URL with timeout
    HttpResponse downloadFileWithTimeout(const std::string& url, 
                                        const std::string& filename, 
                                        int timeout_seconds);
    
    // Make a HTTP GET request
    HttpResponse httpGet(const std::string& url);
    
    // Make a HTTP POST request
    HttpResponse httpPost(const std::string& url, 
                         const std::string& data, 
                         const std::map<std::string, std::string>& headers = {});
    
    // Check if a URL is reachable
    bool isUrlReachable(const std::string& url);
    
    // Encode URL parameters
    std::string urlEncode(const std::string& value);
    
    // Decode URL parameters
    std::string urlDecode(const std::string& value);
    
    // Parse URL into components (scheme, host, path, etc)
    std::map<std::string, std::string> parseUrl(const std::string& url);
    
    // Get MIME type from file extension
    std::string getMimeType(const std::string& filename);
    
    // Check if file exists at URL (HEAD request)
    bool fileExistsAtUrl(const std::string& url);
    
    // Get file size at URL without downloading
    std::optional<size_t> getFileSizeAtUrl(const std::string& url);
}
#include "web.h"
#include "executils.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <cstdlib> 
#include <sstream>
#include <regex>
#include <iomanip>
#include <cstring>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define RESET "\033[0m"

namespace fs = std::filesystem;
using namespace ExecUtils;

namespace WebUtils {

// Helper function to parse HTTP headers from curl output
std::map<std::string, std::string> parseHeaders(const std::string& headerData) {
    std::map<std::string, std::string> headers;
    std::istringstream stream(headerData);
    std::string line;
    
    while (std::getline(stream, line)) {
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Skip empty lines
        if (line.empty()) continue;
        
        // Skip HTTP status line
        if (line.substr(0, 4) == "HTTP") continue;
        
        // Find the colon separator
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            
            // Trim leading/trailing spaces
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            headers[key] = value;
        }
    }
    
    return headers;
}

// Helper function to extract status code from curl output
int extractStatusCode(const std::string& headerData) {
    std::istringstream stream(headerData);
    std::string line;
    
    if (std::getline(stream, line)) {
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Parse HTTP status line
        if (line.substr(0, 4) == "HTTP") {
            std::regex statusRegex("HTTP/\\d\\.\\d\\s+(\\d+)");
            std::smatch match;
            if (std::regex_search(line, match, statusRegex) && match.size() > 1) {
                return std::stoi(match[1].str());
            }
        }
    }
    
    return 0;
}

// URL encoding function
std::string urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else if (c == ' ') {
            escaped << '+';
        } else {
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
        }
    }
    
    return escaped.str();
}

// URL decoding function
std::string urlDecode(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size()) {
            int hex = 0;
            std::istringstream iss(value.substr(i + 1, 2));
            if (iss >> std::hex >> hex) {
                result += static_cast<char>(hex);
                i += 2;
            } else {
                result += value[i];
            }
        } else if (value[i] == '+') {
            result += ' ';
        } else {
            result += value[i];
        }
    }
    
    return result;
}

// Parse URL into components
std::map<std::string, std::string> parseUrl(const std::string& url) {
    std::map<std::string, std::string> components;
    
    // Regular expression for URL parsing
    std::regex urlRegex(
        "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?");
    std::smatch match;
    
    if (std::regex_match(url, match, urlRegex) && match.size() > 9) {
        components["scheme"] = match[2].str();
        components["authority"] = match[4].str();
        components["path"] = match[5].str();
        components["query"] = match[7].str();
        components["fragment"] = match[9].str();
        
        // Parse authority into userinfo, host, and port
        std::string authority = match[4].str();
        std::regex authorityRegex("(?:([^@]*)@)?([^:]+)(?::(\\d+))?");
        std::smatch authorityMatch;
        
        if (std::regex_match(authority, authorityMatch, authorityRegex) && 
            authorityMatch.size() > 3) {
            components["userinfo"] = authorityMatch[1].str();
            components["host"] = authorityMatch[2].str();
            components["port"] = authorityMatch[3].str();
        }
    }
    
    return components;
}

// Get MIME type from file extension
std::string getMimeType(const std::string& filename) {
    static const std::map<std::string, std::string> mimeTypes = {
        {".html", "text/html"},
        {".htm", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".json", "application/json"},
        {".xml", "application/xml"},
        {".txt", "text/plain"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".svg", "image/svg+xml"},
        {".pdf", "application/pdf"},
        {".zip", "application/zip"},
        {".tar", "application/x-tar"},
        {".gz", "application/gzip"},
        {".mp3", "audio/mpeg"},
        {".mp4", "video/mp4"},
        {".wav", "audio/wav"},
        {".avi", "video/x-msvideo"},
        {".bin", "application/octet-stream"}
    };
    
    std::string extension = fs::path(filename).extension().string();
    if (extension.empty()) {
        return "application/octet-stream";
    }
    
    auto it = mimeTypes.find(extension);
    if (it != mimeTypes.end()) {
        return it->second;
    }
    
    return "application/octet-stream";
}

// Download a file using wget or curl
HttpResponse downloadFile(const std::string& url, const std::string& filename) {
    HttpResponse response;
    response.statusCode = 0;
    response.success = false;
    
    try {
        // Create temporary files for headers
        std::string headerFile = filename + ".headers";
        
        // Check for wget
        if (commandExists("wget") == 1) {
            std::cout << GREEN << "Using wget to download " << url << RESET << std::endl;
            
            // Command to download file and save headers
            std::string cmd = "wget -q --server-response -O \"" + filename + "\" \"" + url + 
                             "\" 2> \"" + headerFile + "\"";
            
            // Execute wget command
            std::string result = execCommand(cmd);
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Remove temporary header file
            fs::remove(headerFile);
        }
        // Check for curl
        else if (commandExists("curl") == 1) {
            std::cout << GREEN << "Using curl to download " << url << RESET << std::endl;
            
            // Command to download file and save headers
            std::string cmd = "curl -s -D \"" + headerFile + "\" -L -o \"" + 
                             filename + "\" \"" + url + "\"";
            
            // Execute curl command
            std::string result = execCommand(cmd);
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Remove temporary header file
            fs::remove(headerFile);
        }
        else {
            response.error = "Neither wget nor curl is installed";
            std::cerr << RED << response.error << RESET << std::endl;
            return response;
        }
        
        // Verify download was successful
        if (!fs::exists(filename)) {
            response.error = "Download failed - file not created";
            std::cerr << RED << response.error << RESET << std::endl;
            return response;
        }
        
        // Check if file is empty
        if (fs::file_size(filename) == 0) {
            response.error = "Downloaded file is empty";
            std::cerr << RED << response.error << RESET << std::endl;
            fs::remove(filename);
            return response;
        }
        
        // Read file content
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            response.error = "Failed to open downloaded file";
            std::cerr << RED << response.error << RESET << std::endl;
            return response;
        }
        
        // Load file content into response body
        response.body.assign(std::istreambuf_iterator<char>(file),
                           std::istreambuf_iterator<char>());
        
        response.success = true;
        std::cout << GREEN << "Successfully downloaded " << url << " to " << filename 
                  << " (" << response.body.size() << " bytes)" << RESET << std::endl;
    }
    catch (const std::exception& e) {
        response.error = std::string("Error: ") + e.what();
        std::cerr << RED << response.error << RESET << std::endl;
        
        // Clean up partial file if it exists
        if (fs::exists(filename)) {
            fs::remove(filename);
        }
    }
    
    return response;
}

// Download a file with timeout
HttpResponse downloadFileWithTimeout(const std::string& url, 
                                   const std::string& filename, 
                                   int timeout_seconds) {
    HttpResponse response;
    response.statusCode = 0;
    response.success = false;
    
    try {
        // Create temporary files for headers
        std::string headerFile = filename + ".headers";
        
        // Check for wget
        if (commandExists("wget") == 1) {
            std::cout << GREEN << "Using wget with timeout to download " << url << RESET << std::endl;
            
            // Command to download file with timeout
            std::string cmd = "wget -q --server-response --timeout=" + std::to_string(timeout_seconds) + 
                             " -O \"" + filename + "\" \"" + url + "\" 2> \"" + headerFile + "\"";
            
            // Execute wget command
            std::string result = execCommandWithTimeout(cmd, timeout_seconds + 5);
            
            if (result.find("ERROR: Command timed out") != std::string::npos) {
                response.error = "Download timed out after " + std::to_string(timeout_seconds) + " seconds";
                std::cerr << RED << response.error << RESET << std::endl;
                return response;
            }
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Remove temporary header file
            fs::remove(headerFile);
        }
        // Check for curl
        else if (commandExists("curl") == 1) {
            std::cout << GREEN << "Using curl with timeout to download " << url << RESET << std::endl;
            
            // Command to download file with timeout
            std::string cmd = "curl -s -D \"" + headerFile + "\" -m " + 
                             std::to_string(timeout_seconds) + " -L -o \"" + 
                             filename + "\" \"" + url + "\"";
            
            // Execute curl command
            std::string result = execCommandWithTimeout(cmd, timeout_seconds + 5);
            
            if (result.find("ERROR: Command timed out") != std::string::npos) {
                response.error = "Download timed out after " + std::to_string(timeout_seconds) + " seconds";
                std::cerr << RED << response.error << RESET << std::endl;
                return response;
        }

            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Remove temporary header file
            fs::remove(headerFile);
        }
        else {
            response.error = "Neither wget nor curl is installed";
            std::cerr << RED << response.error << RESET << std::endl;
            return response;
        }
        
        // Verify download was successful
        if (!fs::exists(filename)) {
            response.error = "Download failed - file not created";
            std::cerr << RED << response.error << RESET << std::endl;
            return response;
        }

        // Read file content
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            response.error = "Failed to open downloaded file";
            std::cerr << RED << response.error << RESET << std::endl;
            return response;
        }
        
        // Load file content into response body
        response.body.assign(std::istreambuf_iterator<char>(file),
                           std::istreambuf_iterator<char>());
        
        response.success = true;
        std::cout << GREEN << "Successfully downloaded " << url << " to " << filename 
                  << " (" << response.body.size() << " bytes)" << RESET << std::endl;
    }
    catch (const std::exception& e) {
        response.error = std::string("Error: ") + e.what();
        std::cerr << RED << response.error << RESET << std::endl;
        
        // Clean up partial file if it exists
        if (fs::exists(filename)) {
            fs::remove(filename);
        }
    }
    
    return response;
}

// Make a HTTP GET request
HttpResponse httpGet(const std::string& url) {
    HttpResponse response;
    response.statusCode = 0;
    response.success = false;
    
    try {
        // Create temporary files
        std::string tempFile = fs::temp_directory_path().string() + "/" + 
                              std::to_string(std::time(nullptr)) + ".tmp";
        std::string headerFile = tempFile + ".headers";
        
        // Check for curl
        if (commandExists("curl") == 1) {
            // Command to make GET request
            std::string cmd = "curl -s -D \"" + headerFile + "\" -L -o \"" + 
                             tempFile + "\" \"" + url + "\"";
            
            // Execute curl command
            std::string result = execCommand(cmd);
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Read response body
            std::ifstream bodyStream(tempFile, std::ios::binary);
            response.body.assign(std::istreambuf_iterator<char>(bodyStream),
                               std::istreambuf_iterator<char>());
            bodyStream.close();
            
            // Remove temporary files
            fs::remove(headerFile);
            fs::remove(tempFile);
            
            response.success = true;
        }
        // Check for wget
        else if (commandExists("wget") == 1) {
            // Command to make GET request
            std::string cmd = "wget -q --server-response -O \"" + tempFile + 
                             "\" \"" + url + "\" 2> \"" + headerFile + "\"";
            
            // Execute wget command
            std::string result = execCommand(cmd);
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Read response body
            std::ifstream bodyStream(tempFile, std::ios::binary);
            response.body.assign(std::istreambuf_iterator<char>(bodyStream),
                               std::istreambuf_iterator<char>());
            bodyStream.close();
            
            // Remove temporary files
            fs::remove(headerFile);
            fs::remove(tempFile);
            
            response.success = true;
        }
        else {
            response.error = "Neither curl nor wget is installed";
            std::cerr << RED << response.error << RESET << std::endl;
        }
    }
    catch (const std::exception& e) {
        response.error = std::string("Error: ") + e.what();
        std::cerr << RED << response.error << RESET << std::endl;
    }
    
    return response;
}

// Make a HTTP POST request
HttpResponse httpPost(const std::string& url, 
                    const std::string& data, 
                    const std::map<std::string, std::string>& headers) {
    HttpResponse response;
    response.statusCode = 0;
    response.success = false;
    
    try {
        // Create temporary files
        std::string tempFile = fs::temp_directory_path().string() + "/" + 
                              std::to_string(std::time(nullptr)) + ".tmp";
        std::string headerFile = tempFile + ".headers";
        std::string dataFile = tempFile + ".data";
        
        // Write data to file
        std::ofstream dataStream(dataFile);
        dataStream << data;
        dataStream.close();
        
        // Check for curl
        if (commandExists("curl") == 1) {
            // Build header arguments
            std::string headerArgs;
            for (const auto& [key, value] : headers) {
                headerArgs += " -H \"" + key + ": " + value + "\"";
            }
            
            // Command to make POST request
            std::string cmd = "curl -s -D \"" + headerFile + "\"" + headerArgs + 
                             " -L -d @\"" + dataFile + "\" -o \"" + 
                             tempFile + "\" \"" + url + "\"";
            
            // Execute curl command
            std::string result = execCommand(cmd);
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Read response body
            std::ifstream bodyStream(tempFile, std::ios::binary);
            response.body.assign(std::istreambuf_iterator<char>(bodyStream),
                               std::istreambuf_iterator<char>());
            bodyStream.close();
            
            // Remove temporary files
            fs::remove(headerFile);
            fs::remove(tempFile);
            fs::remove(dataFile);
            
            response.success = true;
        }
        // Check for wget
        else if (commandExists("wget") == 1) {
            // Build header arguments
            std::string headerArgs;
            for (const auto& [key, value] : headers) {
                headerArgs += " --header=\"" + key + ": " + value + "\"";
            }
            
            // Command to make POST request
            std::string cmd = "wget -q --server-response" + headerArgs + 
                             " --post-file=\"" + dataFile + "\" -O \"" + 
                             tempFile + "\" \"" + url + "\" 2> \"" + headerFile + "\"";
            
            // Execute wget command
            std::string result = execCommand(cmd);
            
            // Read headers
            std::ifstream headerStream(headerFile);
            std::string headerData((std::istreambuf_iterator<char>(headerStream)),
                                  std::istreambuf_iterator<char>());
            headerStream.close();
            
            // Extract status code and headers
            response.statusCode = extractStatusCode(headerData);
            response.headers = parseHeaders(headerData);
            
            // Read response body
            std::ifstream bodyStream(tempFile, std::ios::binary);
            response.body.assign(std::istreambuf_iterator<char>(bodyStream),
                       std::istreambuf_iterator<char>());
            bodyStream.close();
            
            // Remove temporary files
            fs::remove(headerFile);
            fs::remove(tempFile);
            fs::remove(dataFile);
            
            response.success = true;
        }
        else {
            response.error = "Neither curl nor wget is installed";
            std::cerr << RED << response.error << RESET << std::endl;
        }
    }
    catch (const std::exception& e) {
        response.error = std::string("Error: ") + e.what();
        std::cerr << RED << response.error << RESET << std::endl;
    }
    
    return response;
}

// Check if a URL is reachable
bool isUrlReachable(const std::string& url) {
    try {
        // Check for curl
        if (commandExists("curl") == 1) {
            // Command to check URL (HEAD request)
            std::string cmd = "curl -s -I -o /dev/null -w \"%{http_code}\" \"" + url + "\"";
            std::string result = execCommand(cmd);
            
            // Parse status code
            int statusCode = 0;
            try {
                statusCode = std::stoi(result);
            } catch (...) {
                return false;
            }
            
            // 2xx and 3xx status codes indicate success
            return (statusCode >= 200 && statusCode < 400);
        }
        // Check for wget
        else if (commandExists("wget") == 1) {
            // Command to check URL (HEAD request)
            std::string cmd = "wget --spider -q \"" + url + "\"";
            int exitCode = std::system(cmd.c_str());
            
            // Exit code 0 indicates success
            return (exitCode == 0);
        }
        else {
            std::cerr << RED << "Neither curl nor wget is installed" << RESET << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::cerr << RED << "Error checking URL: " << e.what() << RESET << std::endl;
        return false;
    }
}

// Check if file exists at URL (HEAD request)
bool fileExistsAtUrl(const std::string& url) {
    return isUrlReachable(url);
}

// Get file size at URL without downloading
std::optional<size_t> getFileSizeAtUrl(const std::string& url) {
    try {
        // Check for curl
        if (commandExists("curl") == 1) {
            // Command to get file size
            std::string cmd = "curl -s -I \"" + url + "\" | grep -i Content-Length | awk '{print $2}'";
            std::string result = execCommand(cmd);
            
            // Trim whitespace
            result.erase(0, result.find_first_not_of(" \t\r\n"));
            result.erase(result.find_last_not_of(" \t\r\n") + 1);
            
            // Parse file size
            if (!result.empty()) {
                try {
                    return std::stoull(result);
                } catch (...) {
                    return std::nullopt;
                }
            }
        }
        // Check for wget
        else if (commandExists("wget") == 1) {
            // Command to get file size
            std::string cmd = "wget --spider -q --server-response \"" + url + "\" 2>&1 | grep -i Content-Length | awk '{print $2}'";
            std::string result = execCommand(cmd);
            
            // Trim whitespace
            result.erase(0, result.find_first_not_of(" \t\r\n"));
            result.erase(result.find_last_not_of(" \t\r\n") + 1);
            
            // Parse file size
            if (!result.empty()) {
                try {
                    return std::stoull(result);
                } catch (...) {
                    return std::nullopt;
                }
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << RED << "Error getting file size: " << e.what() << RESET << std::endl;
    }

    return std::nullopt;
}

} // namespace WebUtils

#!/bin/bash

# LOTL (Living Off The Land) Enumeration Script
# Inspired by LinPEAS but tailored for both Linux and macOS
# Author: LOTL Team
# Version: 1.0

# Usage: ./lotl_enum.sh [--sudo] [--compile-first]
# --sudo: Enable sudo-based checks (will prompt for password)
# --compile-first: Compile the C++ binary before running enumeration

# Parse command line arguments
USE_SUDO=false
COMPILE_FIRST=false

for arg in "$@"; do
    case $arg in
        --sudo)
            USE_SUDO=true
            shift
            ;;
        --compile-first)
            COMPILE_FIRST=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--sudo] [--compile-first]"
            echo "  --sudo         Enable sudo-based checks (will prompt for password)"
            echo "  --compile-first Compile the C++ binary before running enumeration"
            exit 0
            ;;
    esac
done

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Function to compile the C++ binary
compile_binary() {
    echo -e "${BOLD}${BLUE}[+] Compiling LOTL Binary...${RESET}"
    
    if [ -f "Makefile" ]; then
        echo -e "${CYAN}  [*] Running make clean && make...${RESET}"
        if make clean && make; then
            echo -e "${GREEN}  [✓] Compilation successful!${RESET}"
            return 0
        else
            echo -e "${RED}  [!] Compilation failed!${RESET}"
            return 1
        fi
    else
        echo -e "${YELLOW}  [*] Makefile not found, skipping compilation${RESET}"
        return 1
    fi
}

# Function to run the compiled binary
run_binary() {
    echo -e "${BOLD}${BLUE}[+] Running LOTL Binary Analysis...${RESET}"
    
    if [ -f "./lotl" ]; then
        echo -e "${CYAN}  [*] Executing ./lotl...${RESET}"
        ./lotl
        echo -e "${GREEN}  [✓] Binary analysis complete!${RESET}"
    else
        echo -e "${YELLOW}  [*] LOTL binary not found, skipping binary analysis${RESET}"
    fi
}

# Banner
echo -e "${BOLD}${CYAN}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "   LOTL (Living Off The Land) - Privilege Escalation Enumeration Script"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${RESET}"

# Show configuration
echo -e "${BOLD}${BLUE}[+] Configuration${RESET}"
echo -e "${CYAN}  [*] Sudo mode: ${YELLOW}$USE_SUDO${RESET}"
echo -e "${CYAN}  [*] Compile first: ${YELLOW}$COMPILE_FIRST${RESET}"
echo

# Compile if requested
if [ "$COMPILE_FIRST" = true ]; then
    compile_binary
    echo
fi

# Detect OS
OS=$(uname -s)
ARCH=$(uname -m)
KERNEL=$(uname -r)

echo -e "${BOLD}${BLUE}[+] System Information${RESET}"
echo -e "${CYAN}  [*] Operating System: ${YELLOW}$OS${RESET}"
echo -e "${CYAN}  [*] Architecture: ${YELLOW}$ARCH${RESET}"
echo -e "${CYAN}  [*] Kernel Version: ${YELLOW}$KERNEL${RESET}"
echo -e "${CYAN}  [*] Hostname: ${YELLOW}$(hostname)${RESET}"
echo -e "${CYAN}  [*] Current User: ${YELLOW}$(whoami)${RESET}"
echo -e "${CYAN}  [*] User ID: ${YELLOW}$(id)${RESET}"
echo

# Function to check if running as root
check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        echo -e "${RED}${BOLD}[!] WARNING: Running as root! This script is designed for privilege escalation enumeration.${RESET}"
        echo
    fi
}

# Function to find SUID binaries
find_suid() {
    echo -e "${BOLD}${BLUE}[+] SUID/SGID Binaries${RESET}"
    
    if [ "$OS" = "Darwin" ]; then
        # macOS specific SUID search
        echo -e "${CYAN}  [*] Searching for SUID binaries (macOS)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find /usr /bin /sbin /Applications 2>/dev/null -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | while read line; do
                echo -e "${YELLOW}    [SUID] $line${RESET}"
            done
        else
            find /usr /bin /sbin /Applications 2>/dev/null -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | while read line; do
                echo -e "${YELLOW}    [SUID] $line${RESET}"
            done
        fi
        
        echo -e "${CYAN}  [*] Searching for SGID binaries (macOS)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find /usr /bin /sbin /Applications 2>/dev/null -perm -2000 -type f -exec ls -la {} \; 2>/dev/null | while read line; do
                echo -e "${MAGENTA}    [SGID] $line${RESET}"
            done
        else
            find /usr /bin /sbin /Applications 2>/dev/null -perm -2000 -type f -exec ls -la {} \; 2>/dev/null | while read line; do
                echo -e "${MAGENTA}    [SGID] $line${RESET}"
            done
        fi
    else
        # Linux specific SUID search
        echo -e "${CYAN}  [*] Searching for SUID binaries (Linux)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find / -perm -4000 -type f 2>/dev/null | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${YELLOW}    [SUID] $line${RESET}"
                done
            done
        else
            find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${YELLOW}    [SUID] $line${RESET}"
                done
            done
        fi
        
        echo -e "${CYAN}  [*] Searching for SGID binaries (Linux)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find / -perm -2000 -type f 2>/dev/null | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${MAGENTA}    [SGID] $line${RESET}"
                done
            done
        else
            find /usr /bin /sbin /opt -perm -2000 -type f 2>/dev/null | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${MAGENTA}    [SGID] $line${RESET}"
                done
            done
        fi
    fi
    echo
}

# Function to check sudo configuration
check_sudo() {
    echo -e "${BOLD}${BLUE}[+] Sudo Configuration${RESET}"
    
    # Try to list sudo rules without password
    if sudo -n -l 2>/dev/null | grep -q "may run"; then
        echo -e "${GREEN}  [*] Sudo rules found:${RESET}"
        sudo -n -l 2>/dev/null | grep -E "(NOPASSWD|may run)" | while read line; do
            if echo "$line" | grep -q "NOPASSWD"; then
                echo -e "${RED}    [!] $line${RESET}"
            else
                echo -e "${YELLOW}    [*] $line${RESET}"
            fi
        done
    else
        echo -e "${YELLOW}  [*] No sudo rules accessible without password${RESET}"
    fi
    
    # Check sudoers file readability
    if [ -r "/etc/sudoers" ]; then
        echo -e "${RED}  [!] /etc/sudoers is readable!${RESET}"
        grep -v "^#" /etc/sudoers | grep -v "^$" | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    fi
    
    # Check sudoers.d directory
    if [ -d "/etc/sudoers.d" ]; then
        echo -e "${CYAN}  [*] Checking /etc/sudoers.d directory...${RESET}"
        for file in /etc/sudoers.d/*; do
            if [ -r "$file" ]; then
                echo -e "${RED}  [!] $file is readable!${RESET}"
                grep -v "^#" "$file" | grep -v "^$" | while read line; do
                    echo -e "${YELLOW}    $line${RESET}"
                done
            fi
        done
    fi
    echo
}

# Function to check world-writable files
check_world_writable() {
    echo -e "${BOLD}${BLUE}[+] World-Writable Files${RESET}"
    
    if [ "$OS" = "Darwin" ]; then
        # macOS specific search
        echo -e "${CYAN}  [*] Searching for world-writable files (macOS)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find /usr /etc /var /tmp /Applications 2>/dev/null -perm -002 -type f ! -path "*/Trash/*" ! -path "*/Cache/*" | head -20 | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${RED}    [!] $line${RESET}"
                done
            done
        else
            find /usr /etc /var /tmp /Applications 2>/dev/null -perm -002 -type f ! -path "*/Trash/*" ! -path "*/Cache/*" | head -20 | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${RED}    [!] $line${RESET}"
                done
            done
        fi
        
        echo -e "${CYAN}  [*] Searching for world-writable directories (macOS)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find /usr /etc /var /tmp /Applications 2>/dev/null -perm -002 -type d ! -path "*/Trash/*" ! -path "*/Cache/*" | head -10 | while read dir; do
                ls -la "$dir" 2>/dev/null | while read line; do
                    echo -e "${YELLOW}    [WRITABLE DIR] $line${RESET}"
                done
            done
        else
            find /usr /etc /var /tmp /Applications 2>/dev/null -perm -002 -type d ! -path "*/Trash/*" ! -path "*/Cache/*" | head -10 | while read dir; do
                ls -la "$dir" 2>/dev/null | while read line; do
                    echo -e "${YELLOW}    [WRITABLE DIR] $line${RESET}"
                done
            done
        fi
    else
        # Linux specific search
        echo -e "${CYAN}  [*] Searching for world-writable files (Linux)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find / -perm -002 -type f 2>/dev/null ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" | head -20 | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${RED}    [!] $line${RESET}"
                done
            done
        else
            find /tmp /var/tmp /usr /opt /home -perm -002 -type f 2>/dev/null | head -20 | while read file; do
                ls -la "$file" 2>/dev/null | while read line; do
                    echo -e "${RED}    [!] $line${RESET}"
                done
            done
        fi
        
        echo -e "${CYAN}  [*] Searching for world-writable directories (Linux)...${RESET}"
        if [ "$USE_SUDO" = true ]; then
            sudo find / -perm -002 -type d 2>/dev/null ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" | head -10 | while read dir; do
                ls -la "$dir" 2>/dev/null | while read line; do
                    echo -e "${YELLOW}    [WRITABLE DIR] $line${RESET}"
                done
            done
        else
            find /tmp /var/tmp /usr /opt /home -perm -002 -type d 2>/dev/null | head -10 | while read dir; do
                ls -la "$dir" 2>/dev/null | while read line; do
                    echo -e "${YELLOW}    [WRITABLE DIR] $line${RESET}"
                done
            done
        fi
    fi
    echo
}

# Function to check cron jobs
check_cron() {
    echo -e "${BOLD}${BLUE}[+] Cron Jobs${RESET}"
    
    # User crontab
    if crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$"; then
        echo -e "${CYAN}  [*] User crontab:${RESET}"
        crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    fi
    
    # System crontabs
    if [ "$OS" = "Darwin" ]; then
        # macOS cron locations
        if [ "$USE_SUDO" = true ]; then
            for cronfile in /etc/crontab /usr/lib/cron/tabs/*; do
                if [ -f "$cronfile" ]; then
                    echo -e "${CYAN}  [*] $cronfile:${RESET}"
                    sudo grep -v "^#" "$cronfile" 2>/dev/null | grep -v "^$" | while read line; do
                        echo -e "${YELLOW}    $line${RESET}"
                    done
                fi
            done
        else
            for cronfile in /etc/crontab /usr/lib/cron/tabs/*; do
                if [ -r "$cronfile" ]; then
                    echo -e "${CYAN}  [*] $cronfile:${RESET}"
                    grep -v "^#" "$cronfile" | grep -v "^$" | while read line; do
                        echo -e "${YELLOW}    $line${RESET}"
                    done
                fi
            done
        fi
    else
        # Linux cron locations
        if [ "$USE_SUDO" = true ]; then
            for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/*; do
                if [ -f "$cronfile" ]; then
                    echo -e "${CYAN}  [*] $cronfile:${RESET}"
                    sudo grep -v "^#" "$cronfile" 2>/dev/null | grep -v "^$" | while read line; do
                        echo -e "${YELLOW}    $line${RESET}"
                    done
                fi
            done
        else
            for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/*; do
                if [ -r "$cronfile" ]; then
                    echo -e "${CYAN}  [*] $cronfile:${RESET}"
                    grep -v "^#" "$cronfile" | grep -v "^$" | while read line; do
                        echo -e "${YELLOW}    $line${RESET}"
                    done
                fi
            done
        fi
    fi
    echo
}

# Function to check network information
check_network() {
    echo -e "${BOLD}${BLUE}[+] Network Information${RESET}"
    
    echo -e "${CYAN}  [*] Network interfaces:${RESET}"
    if [ "$OS" = "Darwin" ]; then
        ifconfig | grep -E "(inet |ether )" | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    else
        ip addr show 2>/dev/null | grep -E "(inet |link/)" | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    fi
    
    echo -e "${CYAN}  [*] Listening ports:${RESET}"
    if [ "$OS" = "Darwin" ]; then
        netstat -an | grep LISTEN | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    else
        ss -tuln 2>/dev/null | grep LISTEN | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    fi
    echo
}

# Function to check environment variables
check_env() {
    echo -e "${BOLD}${BLUE}[+] Environment Variables${RESET}"
    
    echo -e "${CYAN}  [*] PATH:${RESET}"
    echo -e "${YELLOW}    $PATH${RESET}"
    
    echo -e "${CYAN}  [*] Interesting environment variables:${RESET}"
    env | grep -E "(PASS|KEY|TOKEN|SECRET|API)" | while read line; do
        echo -e "${RED}    [!] $line${RESET}"
    done
    
    if [ "$OS" = "Darwin" ]; then
        echo -e "${CYAN}  [*] macOS specific environment:${RESET}"
        env | grep -E "(HOME|USER|TMPDIR)" | while read line; do
            echo -e "${YELLOW}    $line${RESET}"
        done
    fi
    echo
}

# Function to check processes
check_processes() {
    echo -e "${BOLD}${BLUE}[+] Running Processes${RESET}"
    
    echo -e "${CYAN}  [*] Processes running as root:${RESET}"
    if [ "$OS" = "Darwin" ]; then
        ps aux | grep "^root" | head -10 | while read line; do
            echo -e "${RED}    $line${RESET}"
        done
    else
        ps aux | grep "^root" | head -10 | while read line; do
            echo -e "${RED}    $line${RESET}"
        done
    fi
    echo
}

# Function to check file capabilities (Linux only)
check_capabilities() {
    if [ "$OS" != "Darwin" ]; then
        echo -e "${BOLD}${BLUE}[+] File Capabilities (Linux)${RESET}"
        
        if command -v getcap >/dev/null 2>&1; then
            echo -e "${CYAN}  [*] Files with capabilities:${RESET}"
            getcap -r / 2>/dev/null | while read line; do
                echo -e "${YELLOW}    $line${RESET}"
            done
        else
            echo -e "${YELLOW}  [*] getcap not available${RESET}"
        fi
        echo
    fi
}

# Function to check Docker (if available)
check_docker() {
    echo -e "${BOLD}${BLUE}[+] Docker Information${RESET}"
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "${CYAN}  [*] Docker is installed${RESET}"
        
        # Check if user is in docker group
        if groups | grep -q docker; then
            echo -e "${RED}  [!] User is in docker group - potential privilege escalation!${RESET}"
        fi
        
        # Check docker socket
        if [ -S "/var/run/docker.sock" ]; then
            ls -la /var/run/docker.sock | while read line; do
                echo -e "${YELLOW}    $line${RESET}"
            done
        fi
    else
        echo -e "${YELLOW}  [*] Docker not installed${RESET}"
    fi
    echo
}

# Main execution
check_root
find_suid
check_sudo
check_world_writable
check_cron
check_network
check_env
check_processes
check_capabilities
check_docker

echo -e "${BOLD}${GREEN}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "   LOTL Enumeration Complete!"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${RESET}"

# Run the compiled binary if it exists
run_binary

echo -e "${BOLD}${YELLOW}[+] Summary:${RESET}"
echo -e "${CYAN}  [*] Check RED items for immediate privilege escalation opportunities${RESET}"
echo -e "${CYAN}  [*] Check YELLOW items for potential security issues${RESET}"
echo -e "${CYAN}  [*] Focus on SUID binaries, sudo rules, and world-writable files${RESET}"
echo
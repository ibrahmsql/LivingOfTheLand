#!/bin/bash

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Display banner
show_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo -e "██╗      ██████╗ ████████╗██╗"
    echo -e "██║     ██╔═══██╗╚══██╔══╝██║"
    echo -e "██║     ██║   ██║   ██║   ██║"
    echo -e "██║     ██║   ██║   ██║   ██║"
    echo -e "███████╗╚██████╔╝   ██║   ███████╗"
    echo -e "╚══════╝ ╚═════╝    ╚═╝   ╚══════╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}${BOLD}Living Off The Land Toolkit v2.0${RESET}"
    echo -e "${CYAN}System Security Analysis Tool${RESET}"
    echo -e ""
    echo -e "${BOLD}Author:${RESET} ibrahimsql"
    echo -e "${BOLD}Version:${RESET} v1.0"
    echo -e "${BOLD}Date:${RESET} $(date +"%Y-%m-%d")"
    echo -e ""
    echo -e "${BLUE}${BOLD}=================================================${RESET}"
    echo -e ""
}

# Check dependencies
check_dependencies() {
    echo -e "${BOLD}${BLUE}[*] Checking dependencies...${RESET}"
    
    # Check for C++ compiler
    if command -v g++ &>/dev/null; then
        echo -e "${GREEN}[✓] g++ found${RESET}"
    else
        echo -e "${RED}[!] g++ not found. Installing...${RESET}"
        
        # Detect operating system
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Debian/Ubuntu
            if command -v apt-get &>/dev/null; then
                sudo apt-get update
                sudo apt-get install -y g++ make
            # RHEL/CentOS
            elif command -v yum &>/dev/null; then
                sudo yum install -y gcc-c++ make
            # Arch Linux
            elif command -v pacman &>/dev/null; then
                sudo pacman -S --noconfirm gcc make
            else
                echo -e "${RED}[!] Unsupported Linux distribution. Please install g++ and make packages manually.${RESET}"
                exit 1
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            echo -e "${YELLOW}[!] XCode Command Line Tools installation required for macOS.${RESET}"
            xcode-select --install
        else
            echo -e "${RED}[!] Unsupported operating system: $OSTYPE${RESET}"
            exit 1
        fi
    fi
    
    # Check for make
    if command -v make &>/dev/null; then
        echo -e "${GREEN}[✓] make found${RESET}"
    else
        echo -e "${RED}[!] make not found. Installing...${RESET}"
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Debian/Ubuntu
            if command -v apt-get &>/dev/null; then
                sudo apt-get update
                sudo apt-get install -y make
            # RHEL/CentOS
            elif command -v yum &>/dev/null; then
                sudo yum install -y make
            # Arch Linux
            elif command -v pacman &>/dev/null; then
                sudo pacman -S --noconfirm make
            else
                echo -e "${RED}[!] Unsupported Linux distribution. Please install make package manually.${RESET}"
                exit 1
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            # XCode Command Line Tools installation includes make for macOS
            echo -e "${YELLOW}[!] XCode Command Line Tools installation required for macOS.${RESET}"
            xcode-select --install
        else
            echo -e "${RED}[!] Unsupported operating system: $OSTYPE${RESET}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}[✓] All dependencies installed${RESET}"
}

# Compile LOTL
compile_lotl() {
    echo -e "${BOLD}${BLUE}[*] Compiling LOTL...${RESET}"
    
    # Check if we're in the correct directory
    if [ ! -f "main.cpp" ] || [ ! -d "tools" ] || [ ! -d "core" ]; then
        echo -e "${RED}[!] LOTL source code not found. Make sure you're in the correct directory.${RESET}"
        exit 1
    fi
    
    # Clean build
    make clean
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] make clean error${RESET}"
        exit 1
    fi
    
    # Compile
    make
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Compilation error${RESET}"
        exit 1
    fi
    
    # Check if executable exists
    if [ ! -f "lotl" ]; then
        echo -e "${RED}[!] Compilation completed but lotl executable was not created${RESET}"
        exit 1
    fi
    
    # Make it executable
    chmod +x lotl
    
    echo -e "${GREEN}[✓] LOTL successfully compiled${RESET}"
}

# Run LOTL
run_lotl() {
    echo -e "${BOLD}${BLUE}[*] Running LOTL...${RESET}"
    echo -e "${YELLOW}[!] Press CTRL+C to exit${RESET}"
    sleep 2
    
    # Run LOTL
    ./lotl
}

# Main function
main() {
    show_banner
    check_dependencies
    compile_lotl
    
    echo -e ""
    echo -e "${BOLD}${BLUE}[*] LOTL installation complete${RESET}"
    echo -e ""
    
    # Ask user if they want to run LOTL
    read -p "$(echo -e ${BOLD}"Do you want to run LOTL now? (y/n): "${RESET})" choice
    
    case "$choice" in
        y|Y|yes|Yes|YES)
            run_lotl
            ;;
        *)
            echo -e "${YELLOW}[*] You can run LOTL later using the ./lotl command${RESET}"
            ;;
    esac
}

# Call main function
main 
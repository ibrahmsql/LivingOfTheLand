# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -g -pthread

# Directories
SRC_DIR = .
CORE_DIR = core
TOOLS_DIR = tools

# Source and object files
SRCS = $(SRC_DIR)/main.cpp \
       $(CORE_DIR)/init.cpp \
       $(TOOLS_DIR)/suids.cpp \
       $(TOOLS_DIR)/executils.cpp \
       $(TOOLS_DIR)/web.cpp \
       $(TOOLS_DIR)/cronanalyzer.cpp \
       $(TOOLS_DIR)/kernelvulnscan.cpp \
       $(TOOLS_DIR)/sudoanalyzer.cpp \
       $(TOOLS_DIR)/containeranalyzer.cpp \
       $(TOOLS_DIR)/networkanalyzer.cpp \
       $(TOOLS_DIR)/cveanalyzer.cpp \
       $(TOOLS_DIR)/systemanalyzer.cpp \
       $(TOOLS_DIR)/dockeranalyzer.cpp

OBJS = $(SRCS:.cpp=.o)

# Output binary
TARGET = lotl

# Default build
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Rebuild if headers change
$(SRC_DIR)/main.o: $(CORE_DIR)/init.h $(TOOLS_DIR)/suids.h $(TOOLS_DIR)/executils.h $(TOOLS_DIR)/web.h $(TOOLS_DIR)/cronanalyzer.h $(TOOLS_DIR)/kernelvulnscan.h $(TOOLS_DIR)/sudoanalyzer.h $(TOOLS_DIR)/containeranalyzer.h $(TOOLS_DIR)/networkanalyzer.h $(TOOLS_DIR)/cveanalyzer.h $(TOOLS_DIR)/systemanalyzer.h $(TOOLS_DIR)/dockeranalyzer.h
$(CORE_DIR)/init.o: $(CORE_DIR)/init.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/suids.o: $(TOOLS_DIR)/suids.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/executils.o: $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/web.o: $(TOOLS_DIR)/web.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/cronanalyzer.o: $(TOOLS_DIR)/cronanalyzer.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/kernelvulnscan.o: $(TOOLS_DIR)/kernelvulnscan.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/sudoanalyzer.o: $(TOOLS_DIR)/sudoanalyzer.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/containeranalyzer.o: $(TOOLS_DIR)/containeranalyzer.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/networkanalyzer.o: $(TOOLS_DIR)/networkanalyzer.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/cveanalyzer.o: $(TOOLS_DIR)/cveanalyzer.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/systemanalyzer.o: $(TOOLS_DIR)/systemanalyzer.h $(TOOLS_DIR)/executils.h
$(TOOLS_DIR)/dockeranalyzer.o: $(TOOLS_DIR)/dockeranalyzer.h $(TOOLS_DIR)/executils.h

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Optional: force rebuild
rebuild: clean all

# Install target
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin"
	@sudo cp $(TARGET) /usr/local/bin/
	@echo "Installation complete"

# Uninstall target
uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin"
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstallation complete"

.PHONY: all clean rebuild install uninstall

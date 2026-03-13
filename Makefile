# ============================================================
# Log Threat Analyzer — Makefile
# Usage:
#   make          → build the engine
#   make clean    → remove compiled files
#   make run      → build and run terminal interface
# ============================================================

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
SRC      = engine/engine.cpp
TARGET   = engine/engine

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
	@echo "✅ Build successful: $(TARGET)"

clean:
	rm -f $(TARGET)
	@echo "🧹 Cleaned build artifacts"

run: all
	python3 backend/terminal.py

.PHONY: all clean run

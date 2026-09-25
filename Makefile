CC ?= gcc
CFLAGS = -fopenmp -Wall -Wextra -g -O3 -std=c23 -Iinclude -Isrc/mprec
LDFLAGS = -lgmp -lcrypto -lm -fopenmp

# Directories
TEMP_DIR = temp
BIN_DIR = bin

# Target executable
TARGET = $(BIN_DIR)/mprec_app

# Source directories
SRC_DIRS = src/mprec src/crypto src/ui src/tests tests

# Find all .c files in SRC_DIRS and root (if any)
SRCS = $(wildcard *.c) $(wildcard $(addsuffix /*.c, $(SRC_DIRS)))
OBJS = $(patsubst %.c, $(TEMP_DIR)/%.o, $(notdir $(SRCS)))

# Tell make to search for .c files across all source directories
vpath %.c . $(SRC_DIRS)

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Pattern rule for object files stored in $(TEMP_DIR)
$(TEMP_DIR)/%.o: %.c | $(TEMP_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create directories if they don't exist
$(TEMP_DIR):
	mkdir -p $(TEMP_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(TEMP_DIR) $(BIN_DIR)

.PHONY: all run clean
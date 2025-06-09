##
# Makefile for EchoRDS
#
# This Makefile builds the EchoRDS project components.
##

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic -g -D_DEFAULT_SOURCE
LDFLAGS = -lssl -lcrypto -lz -luuid

# Directories
SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
LIB_DIR = lib

# Source files
CORE_SRC = $(SRC_DIR)/echords.c $(SRC_DIR)/crypto.c $(SRC_DIR)/spb490.c $(SRC_DIR)/json.c
GATEWAY_SRC = $(SRC_DIR)/gateway/gateway.c $(SRC_DIR)/gateway/main.c
RECEIVER_SRC = $(SRC_DIR)/receiver/receiver.c $(SRC_DIR)/receiver/main.c
UTILS_SRC = $(SRC_DIR)/utils/key_generator.c

# Object files
CORE_OBJ = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(CORE_SRC))
GATEWAY_OBJ = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(GATEWAY_SRC))
RECEIVER_OBJ = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(RECEIVER_SRC))
UTILS_OBJ = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(UTILS_SRC))

# Targets
GATEWAY_BIN = $(BIN_DIR)/echords_gateway
RECEIVER_BIN = $(BIN_DIR)/echords_receiver
KEYGEN_BIN = $(BIN_DIR)/echords_keygen

# Default target
all: directories $(GATEWAY_BIN) $(RECEIVER_BIN) $(KEYGEN_BIN)

# Create directories
directories:
	@mkdir -p $(OBJ_DIR)/gateway $(OBJ_DIR)/receiver $(OBJ_DIR)/utils $(BIN_DIR)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Link gateway
$(GATEWAY_BIN): $(CORE_OBJ) $(GATEWAY_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Link receiver
$(RECEIVER_BIN): $(CORE_OBJ) $(RECEIVER_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Link key generator
$(KEYGEN_BIN): $(CORE_OBJ) $(UTILS_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Install
install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(GATEWAY_BIN) $(DESTDIR)/usr/local/bin
	install -m 755 $(RECEIVER_BIN) $(DESTDIR)/usr/local/bin
	install -m 755 $(KEYGEN_BIN) $(DESTDIR)/usr/local/bin

# Uninstall
uninstall:
	rm -f $(DESTDIR)/usr/local/bin/echords_gateway
	rm -f $(DESTDIR)/usr/local/bin/echords_receiver
	rm -f $(DESTDIR)/usr/local/bin/echords_keygen

.PHONY: all directories clean install uninstall

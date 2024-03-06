CC = x86_64-w64-mingw32-g++
CFLAGS = -I../fetch/include -I../loader/include -std=c++17 -g -O2 -Wno-write-strings -fno-exceptions -fmerge-all-constants
LDFLAGS = -L../fetch -lfetch -L../loader -lloader -static-libgcc -static-libstdc++ -static -lsodium 

SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

# Source files
SRCS = $(shell find $(SRC_DIR) -type f -name '*.cpp')
OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# Executable name
EXECUTABLE = 0518.exe

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(EXECUTABLE)

.PHONY: clean
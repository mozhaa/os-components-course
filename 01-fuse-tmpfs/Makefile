CC = gcc
CFLAGS = -Iinclude
LDFLAGS = `pkg-config fuse3 --libs`
PKG_CFLAGS = `pkg-config fuse3 --cflags`

OBJ_DIR = obj
SRCS = src/tmpfs.c src/state.c
OBJS = $(addprefix $(OBJ_DIR)/, $(notdir $(SRCS:.c=.o)))
TARGET = tmpfs

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: src/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean

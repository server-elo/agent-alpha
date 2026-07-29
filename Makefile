CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Werror=return-type -O2 -Iinclude -Ideps -pthread
LDFLAGS = -lcurl -pthread

SRC = src/main.c src/agent_loop.c src/llm.c src/tools.c src/browser.c src/telegram.c deps/cJSON.c deps/sds.c
OBJ = $(SRC:.c=.o)
TARGET = alpha

.PHONY: all clean run telegram repl install

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c include/alpha.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps/%.o: deps/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)

run: $(TARGET)
	./$(TARGET) $(ARGS)

telegram: $(TARGET)
	./scripts/alpha-telegram.sh start

repl: $(TARGET)
	./$(TARGET) --repl

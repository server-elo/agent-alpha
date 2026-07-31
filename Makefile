CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Werror=return-type -O2 -Iinclude -Ideps -pthread
LDFLAGS = -lcurl -pthread

SRC = src/main.c src/agent_loop.c src/llm.c src/tools.c src/browser.c src/telegram.c deps/cJSON.c deps/sds.c
OBJ = $(SRC:.c=.o)
TARGET = alpha

.PHONY: all clean run telegram repl install test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c include/alpha.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps/%.o: deps/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Tests include the module under test directly to reach its static functions,
# so they compile their own copy -- and must therefore depend on that .c file.
# Without it make considers a test up to date after the module changed, and
# silently re-runs a stale binary (observed: a deliberately broken source
# still reported all checks passing).
TEST_SRC = tests/test_tools.c tests/test_session.c tests/test_telegram.c
TEST_BIN = $(TEST_SRC:tests/%.c=tests/bin/%)
TEST_DEPS = src/browser.o deps/cJSON.o deps/sds.o

tests/bin/test_tools: tests/test_tools.c src/tools.c $(TEST_DEPS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< $(TEST_DEPS) $(LDFLAGS)

tests/bin/test_session: tests/test_session.c src/agent_loop.c src/llm.o src/tools.o $(TEST_DEPS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< src/llm.o src/tools.o $(TEST_DEPS) $(LDFLAGS)

# The voice timeout is 3 minutes in production; the suite must not wait that
# long to prove a wedged transcriber gets killed, so it is compiled short.
tests/bin/test_telegram: tests/test_telegram.c src/telegram.c src/agent_loop.o src/llm.o src/tools.o $(TEST_DEPS) | tests/bin
	$(CC) $(CFLAGS) -DALPHA_VOICE_TIMEOUT_MS=3000 -o $@ $< src/agent_loop.o src/llm.o src/tools.o $(TEST_DEPS) $(LDFLAGS)

tests/bin:
	mkdir -p tests/bin

test: $(TEST_BIN)
	@fail=0; for t in $(TEST_BIN); do \
		echo "=== $$t ==="; ./$$t || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi

clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf tests/bin

run: $(TARGET)
	./$(TARGET) $(ARGS)

telegram: $(TARGET)
	./scripts/alpha-telegram.sh start

repl: $(TARGET)
	./$(TARGET) --repl

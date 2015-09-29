SRC = src/ae.c src/anet.c
OBJ = ${SRC:.c=.o}
CFLAGS = -Wno-parentheses -Wno-switch-enum -Wno-unused-value

all:libae.a timer echo server_test client_test

libae.a: $(OBJ)
	$(AR) -rc $@ $(OBJ)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

timer: example/timer.o libae.a
	$(CC) $^ -o $@

echo: example/echo.o libae.a
	$(CC) $^ -o $@

server_test: example/server_test.o libae.a
	$(CC) $^ -o $@

client_test: example/client_test.o libae.a
	$(CC) $^ -o $@

clean:
	rm -f $(OBJ) libae.a example/*.o libae.a timer echo server_test client_test

.PHONY: clean

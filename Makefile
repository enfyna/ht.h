CFLAGS=-Wall -Wextra -O0 -fsanitize=address,undefined,leak,integer -ggdb -pedantic

default: example

example:
	clang $(CFLAGS) example.c -o build/$@ -I. 

PHONY: clean
clean:
	rm build/example

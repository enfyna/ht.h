CFLAGS=-Wall -Wextra -O0 -fsanitize=address,undefined,leak,integer -ggdb -pedantic

default: main

main:
	clang $(CFLAGS) main.c -o build/$@ -I. 

PHONY: clean
clean:
	rm build/main

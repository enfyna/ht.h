CFLAGS=-Wall -Wextra -fsanitize=address -ggdb -pedantic

default: main

main:
	clang $(CFLAGS) main.c -o build/$@ -I. 

PHONY: clean
clean:
	rm build/main

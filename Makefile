all: compile run

compile: a.out

vcrypto-test: main.c vibrato-crypto.c
	gcc main.c vibrato-crypto.c -lsodium -o vcrypto-test

run:
	./a.out

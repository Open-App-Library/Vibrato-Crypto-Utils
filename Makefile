all: compile run

compile: a.out

a.out: main.c vibrato-crypto.c
	gcc main.c vibrato-crypto.c -lsodium

run:
	./a.out

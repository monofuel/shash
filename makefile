all: shash

shash: shash.c shash.h
	gcc -pedantic -std=gnu99 -Wall -lcrypto -g -m64 -o shash shash.c

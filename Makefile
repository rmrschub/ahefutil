CC = g++
CFLAGS = -std=c++14 -O2 -Wall -pedantic
INCLUDES = -I /usr/local/include
LFLAGS = -L /usr/local/lib
LIBS = -pthread -lgcrypt -lboost_program_options

TARGET = genpkey extract encrypt decrypt addenc

all: genpkey extract encrypt decrypt addenc

genpkey:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/genpkey src/genpkey.cpp

extract:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/extract src/extract.cpp

encrypt:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/encrypt src/encrypt.cpp

decrypt:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/decrypt src/decrypt.cpp

addenc:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/addenc src/addenc.cpp
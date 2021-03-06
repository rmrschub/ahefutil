CC = g++
CFLAGS = -std=c++14 -O2 -Wall -pedantic
INCLUDES = -I /usr/local/include
LFLAGS = -L /usr/local/lib
LIBS = -pthread -lgcrypt -lboost_program_options -lgmp -lm

all: genpkey extract encrypt decrypt addenc subenc mulenc

genpkey:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/genpkey src/genpkey.cpp

extract:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/extract src/extract.cpp

encrypt:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/encrypt src/encrypt.cpp

decrypt:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/decrypt src/decrypt.cpp

addenc:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/addenc src/addenc_gmp.cpp

subenc:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/subenc src/subenc_gmp.cpp

mulenc:
	$(CC) $(CFLAGS) $(INCLUDES) $(LFLAGS) $(LIBS) -o bin/mulenc src/mulenc_gmp.cpp
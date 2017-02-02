# no time to make this Makefile run...

genpkey: 
    g++ -std=c++14 -O2 -Wall -I /usr/local/include -L /usr/local/lib -pedantic -pthread -lgcrypt -lboost_program_options -o genpkey genpkey.cpp

extract:
    g++ -std=c++14 -O2 -Wall -I /usr/local/include -L /usr/local/lib -pedantic -pthread -lgcrypt -lboost_program_options -o extract extract.cpp

encrypt:
    g++ -std=c++14 -O2 -Wall -I /usr/local/include -L /usr/local/lib -pedantic -pthread -lgcrypt -lboost_program_options -o encrypt encrypt.cpp

decrypt:
    g++ -std=c++14 -O2 -Wall -I /usr/local/include -L /usr/local/lib -pedantic -pthread -lgcrypt -lboost_program_options -o decrypt decrypt.cpp
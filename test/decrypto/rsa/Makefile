SRC:=$(wildcard *.cpp)

all:
	$(CXX) -g $(SRC)  -o rsa-decrypto -lssl -lcrypto -lmysqlcppconn -lmysqlclient

.PHONY:clean
clean:
	$(RM) rsa-decrypto

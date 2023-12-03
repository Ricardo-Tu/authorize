SRC:=$(wildcard *.cpp)

all:
	$(CXX) -g $(SRC)  -o rsa-encrypto -lssl -lcrypto -lmysqlcppconn -lmysqlclient

.PHONY:clean
clean:
	$(RM) rsa-encrypto

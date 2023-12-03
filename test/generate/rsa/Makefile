
all:
	$(CXX) -g main.cpp generateKey.cpp files.cpp  -o rsa-generatekey -lssl -lcrypto 

.PHONY:clean
clean:
	$(RM) rsa-generatekey 

cleanfile:
	$(RM) priv.txt pub.txt

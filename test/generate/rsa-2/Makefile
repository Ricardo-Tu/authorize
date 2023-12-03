
all:
	$(CXX) -g main.cpp scrsa.cpp  -o rsa-generatekey -lssl -lcrypto

.PHONY:clean
clean:
	$(RM) rsa-generatekey 

cleanfile:
	$(RM) priv.txt pub.txt

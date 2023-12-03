####  Makefile for compilation using GNU GCC or clang  ####

OPT=-O	 # Optimization option by default
ARCH=x64
CC=gcc
CXX=g++
ifeq "$(CC)" "gcc"
	COMPILER=gcc
else ifeq "$(CC)" "clang"
	COMPILER=clang
endif

ifeq "$(ARCH)" "x64"
	ARCHITECTURE=_AMD64_
ifeq "$(GENERIC)" "TRUE"
	USE_GENERIC=-D _GENERIC_
endif
ifeq "$(ASM)" "FALSE"
else ifeq "$(ASM)" "TRUE"
	USE_ASM=-D _ASM_
	ASM_var=yes
else
ifneq "$(GENERIC)" "TRUE"
	USE_ASM=-D _ASM_
	ASM_var=yes
endif
endif
ifeq "$(AVX)" "FALSE"
else ifeq "$(AVX)" "TRUE"
	USE_AVX=-D _AVX_
	SIMD=-mavx
else
ifneq "$(GENERIC)" "TRUE"
	USE_AVX=-D _AVX_
	SIMD=-mavx
endif  	
endif
ifeq "$(AVX2)" "FALSE"
else ifeq "$(AVX2)" "TRUE"
	USE_AVX2=-D _AVX2_
	SIMD=-mavx2
	AVX2_var=yes
else
ifneq "$(GENERIC)" "TRUE"
	USE_AVX2=-D _AVX2_
	SIMD=-mavx2
	AVX2_var=yes
endif  	
endif

else ifeq "$(ARCH)" "ARM64"
	ARCHITECTURE=_ARM64_
	ARM_SETTING=-lrt
ifeq "$(GENERIC)" "TRUE"
	USE_GENERIC=-D _GENERIC_
endif

else

USE_GENERIC=-D _GENERIC_
ifeq "$(GENERIC)" "FALSE"
	USE_GENERIC=
endif
ifeq "$(ASM)" "TRUE"
	USE_ASM=-D _ASM_
endif
ifeq "$(AVX)" "TRUE"
	USE_ASM=-D _ASM_
endif
ifeq "$(AVX2)" "TRUE"
	USE_ASM=-D _ASM_
endif
ifeq "$(ARCH)" "x86"
	ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
	ARCHITECTURE=_ARM_
	ARM_SETTING=-lrt
endif
endif

ADDITIONAL_SETTINGS=-fwrapv -fomit-frame-pointer -march=native
ifeq "$(EXTENDED_SET)" "FALSE"
	ADDITIONAL_SETTINGS=
endif

USE_ENDOMORPHISMS=-D USE_ENDO
ifeq "$(USE_ENDO)" "FALSE"
	USE_ENDOMORPHISMS=
endif

ifeq "$(SERIAL_PUSH)" "TRUE"
	USE_SERIAL_PUSH=-D PUSH_SET
endif

SHARED_LIB_TARGET=libFourQ.so
ifeq "$(SHARED_LIB)" "TRUE"
	DO_MAKE_SHARED_LIB=-fPIC
	LIBFLAG= -shared -fPIC	
	SHARED_LIB_O=$(SHARED_LIB_TARGET)
endif

LIBFLAG=
ifeq "$(SHARED_FILE)" "TRUE"
	LIBFLAG= -shared -fPIC	
endif

cc=$(COMPILER)
CFLAGS=-c $(OPT) $(ADDITIONAL_SETTINGS) $(SIMD) -D $(ARCHITECTURE) -D __LINUX__ $(USE_AVX) $(USE_AVX2) $(USE_ASM) $(USE_GENERIC) $(USE_ENDOMORPHISMS) $(USE_SERIAL_PUSH) $(DO_MAKE_SHARED_LIB) -Wall -DDEBUG $(LIBFLAG)
LDFLAGS=
ifdef ASM_var
ifdef AVX2_var
	ASM_OBJECTS=fp2_1271_AVX2.o
else
	ASM_OBJECTS=fp2_1271.o
endif 
endif
OBJECTS=eccp2.o eccp2_no_endo.o eccp2_core.o $(ASM_OBJECTS) crypto_util.o schnorrq.o hash_to_curve.o kex.o sha512.o random.o 
OBJECTS_FP_TEST=fp_tests.o $(OBJECTS) test_extras.o 
OBJECTS_ECC_TEST=ecc_tests.o $(OBJECTS) test_extras.o 
OBJECTS_CRYPTO_TEST=crypto_tests.o $(OBJECTS) test_extras.o 
OBJECTS_ALL=$(OBJECTS) $(OBJECTS_FP_TEST) $(OBJECTS_ECC_TEST) $(OBJECTS_CRYPTO_TEST)
CRYPTOOBJ=$(OBJECTS) test_extras.o scrsa.o getinfo.o
HWINFOINC:=-I../headerfiles/
HWINFOOBJ:=battery.o cpu.o disk.o gpu.o mainboard.o os.o ram.o system.o filesystem.o
PYBINDFLAG:= -O3 -Wall -shared -std=c++17 -fPIC `python3-config --ldflags`  `python3 -m pybind11 --includes`
PYBINDHEAD:= -I/usr/local/include  -I/usr/include  -I/usr/include/python3.10
TESTOBJ=$(OBJECTS) test_extras.o mytest.o
HARDWAREINFOOBJ=$(HWINFOOBJ)  $(CRYPTOOBJ) hardwareinfo.o 
LIBHARDWAREINFOOBJ=$(HWINFOOBJ)  $(CRYPTOOBJ) HwInfo.o HwInfo_bind.o
AUTHORIZEOBJ=$(HWINFOOBJ)  $(CRYPTOOBJ) authorize.o 
LIBAUTHORIZEOBJ=$(HWINFOOBJ)  $(CRYPTOOBJ) HwInfo_authorize.o HwInfo_authorize_bind.o

all: crypto_test ecc_test fp_test $(SHARED_LIB_O) mytest libHwInfo libHwInfo_authorize

.PHONY: vm
vm: $(HARDWAREINFOOBJ) host-server.o guest-client.o authorize.o
	$(CXX) host-server.o	$(HARDWAREINFOOBJ) -o server -lssl -lcrypto -lpthread 
	$(CXX) guest-client.o authorize.o	$(HARDWAREINFOOBJ)	-o client -lssl -lcrypto -lpthread 

ifeq "$(SHARED_LIB)" "TRUE"
	$(SHARED_LIB_O): $(OBJECTS)
		$(CC) -shared -o $(SHARED_LIB_O) $(OBJECTS)
endif


host-server.o: ../host-server.cpp
	$(CXX) $(CFLAGS) ../host-server.cpp

guest-client.o: ../guest-client.cpp
	$(CXX) $(CFLAGS) ../guest-client.cpp

mytest: $(TESTOBJ) 
	$(CXX) -o mytest $(TESTOBJ) $(ARM_SETTING)

libHwInfo: $(LIBHARDWAREINFOOBJ)
	$(CXX) $(LIBHARDWAREINFOOBJ) $(PYBINDFLAG) $(PYBINDHEAD) -o libHwInfo.so  -lssl -lcrypto

libHwInfo_authorize: $(LIBAUTHORIZEOBJ)
	$(CXX) $(LIBAUTHORIZEOBJ) $(PYBINDFLAG) $(PYBINDHEAD) -o libHwInfo_authorize.so  -lssl -lcrypto

crypto_test: $(OBJECTS_CRYPTO_TEST)
	$(CC) -o crypto_test $(OBJECTS_CRYPTO_TEST) $(ARM_SETTING)

ecc_test: $(OBJECTS_ECC_TEST)
	$(CC) -o ecc_test $(OBJECTS_ECC_TEST) $(ARM_SETTING)

fp_test: $(OBJECTS_FP_TEST)
	$(CC) -o fp_test $(OBJECTS_FP_TEST) $(ARM_SETTING)

eccp2_core.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/eccp2_core.c ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/fp_x64.h
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/eccp2_core.c

eccp2.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/eccp2.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/eccp2.c

eccp2_no_endo.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/eccp2_no_endo.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/eccp2_no_endo.c
	
ifdef ASM_var
ifdef AVX2_var
    ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/consts.s: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/consts.c
	    $(CC) $(CFLAGS) -S -o $@ $<
	    sed '/.globl/d' -i $@
    fp2_1271_AVX2.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/fp2_1271_AVX2.S ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/consts.s
	    $(CC) $(CFLAGS) -o $@ $<
else
    fp2_1271.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/fp2_1271.S
	    $(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/fp2_1271.S
endif
endif

mytest.o: ../mytest.cpp
	$(CXX) $(CFLAGS) ../mytest.cpp

hardwareinfo.o: ../hardwareinfo.cpp
	$(CXX) $(CFLAGS) ../hardwareinfo.cpp

HwInfo.o: ../HwInfo.cpp
	$(CXX) $(CFLAGS) ../HwInfo.cpp

HwInfo_bind.o: ../bind/HwInfo_bind.cpp
	$(CXX) $(CFLAGS) $(PYBINDFLAG) $(PYBINDHEAD) ../bind/HwInfo_bind.cpp

authorize.o: ../authorize.cpp
	$(CXX) $(CFLAGS) ../authorize.cpp

HwInfo_authorize.o: ../HwInfo_authorize.cpp
	$(CXX) $(CFLAGS) ../HwInfo_authorize.cpp

HwInfo_authorize_bind.o: ../bind/HwInfo_authorize_bind.cpp
	$(CXX) $(CFLAGS) $(PYBINDFLAG) $(PYBINDHEAD) ../bind/HwInfo_authorize_bind.cpp

scrsa.o: ../sourcefiles/crypto/rsa/scrsa.cpp
	$(CXX) $(CFLAGS) ../sourcefiles/crypto/rsa/scrsa.cpp -lssl -lcrypto

getinfo.o: ../sourcefiles/hwinfo/getinfo.cpp
	$(CXX) $(CFLAGS) ../sourcefiles/hwinfo/getinfo.cpp

battery.o: battery1.o battery2.o 
	ld -r -o battery.o battery1.o battery2.o

battery1.o: ../sourcefiles/hwinfo/src/battery.cpp
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/battery.cpp -o battery1.o

battery2.o: ../sourcefiles/hwinfo/src/linux/battery.cpp
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/battery.cpp -o battery2.o

cpu.o: cpu1.o cpu2.o  
	ld -r -o cpu.o cpu1.o cpu2.o

cpu1.o: ../sourcefiles/hwinfo/src/cpu.cpp
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/cpu.cpp -o cpu1.o 

cpu2.o: ../sourcefiles/hwinfo/src/linux/cpu.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/cpu.cpp -o cpu2.o

disk.o: disk1.o  disk2.o
	ld -r -o disk.o disk1.o disk2.o 

disk1.o: ../sourcefiles/hwinfo/src/disk.cpp 
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/disk.cpp -o disk1.o 

disk2.o: ../sourcefiles/hwinfo/src/linux/disk.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/disk.cpp  -o disk2.o

gpu.o: gpu1.o gpu2.o 
	ld -r -o gpu.o gpu1.o gpu2.o

gpu1.o: ../sourcefiles/hwinfo/src/gpu.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/gpu.cpp  -o gpu1.o

gpu2.o: ../sourcefiles/hwinfo/src/linux/gpu.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/gpu.cpp  -o gpu2.o

mainboard.o: mainboard1.o mainboard2.o 
	ld -r -o mainboard.o mainboard1.o mainboard2.o

mainboard1.o: ../sourcefiles/hwinfo/src/mainboard.cpp 
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/mainboard.cpp -o mainboard1.o 

mainboard2.o: ../sourcefiles/hwinfo/src/linux/mainboard.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/mainboard.cpp -o mainboard2.o 

os.o: os1.o os2.o
	ld -r -o os.o os1.o os2.o

os1.o: ../sourcefiles/hwinfo/src/os.cpp 
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/os.cpp -o os1.o 

os2.o: ../sourcefiles/hwinfo/src/linux/os.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/os.cpp -o os2.o 

ram.o: ram1.o ram2.o 
	ld -r -o ram.o ram1.o ram2.o

ram1.o: ../sourcefiles/hwinfo/src/ram.cpp  
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/ram.cpp -o ram1.o 

ram2.o: ../sourcefiles/hwinfo/src/linux/ram.cpp 
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/ram.cpp -o ram2.o

system.o: ../sourcefiles/hwinfo/src/system.cpp 
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/system.cpp

filesystem.o: ../sourcefiles/hwinfo/src/linux/utils/filesystem.cpp
	$(CXX) $(HWINFOINC)  $(CFLAGS) ../sourcefiles/hwinfo/src/linux/utils/filesystem.cpp

schnorrq.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/schnorrq.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/schnorrq.c

hash_to_curve.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/hash_to_curve.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/hash_to_curve.c

kex.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/kex.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/kex.c

crypto_util.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/crypto_util.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/crypto_util.c

sha512.o: ../sourcefiles/crypto/FourQlib/sha512/sha512.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/sha512/sha512.c

random.o: ../sourcefiles/crypto/FourQlib/random/random.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/random/random.c

test_extras.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/test_extras.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/test_extras.c

crypto_tests.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/crypto_tests.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/crypto_tests.c

ecc_tests.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/ecc_tests.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/ecc_tests.c

fp_tests.o: ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/fp_tests.c
	$(CC) $(CFLAGS) ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/fp_tests.c

.PHONY: clean

clean:
	rm -rf $(SHARED_LIB_TARGET) crypto_test ecc_test fp_test *.o ../sourcefiles/crypto/FourQlib/FourQ_64bit_and_portable/AMD64/consts.s mytest server client libHwInfo.so libHwInfo_authorize.so 


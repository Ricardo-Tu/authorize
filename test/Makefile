OPT=-O3	 
CC=g++
ARCH=x64
ifeq "$(CC)" "g++"
	COMPILER=g++
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
	SHARED_LIB_O=$(SHARED_LIB_TARGET)
endif
CFLAGS:=$(OPT) $(ADDITIONAL_SETTINGS) $(SIMD) -D $(ARCHITECTURE) -D __LINUX__ $(USE_AVX) $(USE_AVX2) $(USE_ASM) $(USE_GENERIC) $(USE_ENDOMORPHISMS) $(USE_SERIAL_PUSH) $(DO_MAKE_SHARED_LIB)
INC:=-I../headerfiles/crypto/FourQlib/FourQ_64bit_and_portable/tests  -I../headerfiles/crypto/FourQlib/FourQ_64bit_and_portable/
SRC:=../headerfiles/crypto/FourQlib/FourQ_64bit_and_portable/tests/test_extras.c

all: ecc-test
	@echo "Hello, World!"

ecc-test: lib
	$(CXX) ecc-test.cpp $(SRC) $(INC) $(CFLAGS) -o ecc-test -L../headerfiles/crypto/FourQlib/FourQ_64bit_and_portable/ -lFourQ

lib:
	$(MAKE) -C ../headerfiles/crypto/FourQlib/FourQ_64bit_and_portable/ ARCH=x64 SHARED_LIB=TRUE

.PHONY: clean
clean:
	$(RM) ecc-test
	$(MAKE) -C ../headerfiles/crypto/FourQlib/FourQ_64bit_and_portable/ clean 
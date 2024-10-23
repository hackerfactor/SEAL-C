####################################################################
# SEAL makefile
# See LICENSE.md
####################################################################
CXXFLAGS=-O2 -Wall

# DEBUG=0 = disabled
# DEBUG=1 = symbols
# DEBUG=2 = gprof enabled
DEBUG=0

#CXXFLAGS=-std=c++17

ifeq ($(DEBUG),0)
  STRIP=strip -x
else
  CXXFLAGS += -g
  CXXFLAGS += -lefence
endif
ifeq ($(DEBUG),2)
  CXXFLAGS += -pg
endif

INC = -Isrc
LIB = -L/usr/local/lib -lresolv -lcrypto -lssl -lcurl
EXE = bin/sealtool

all: $(EXE)


clean:
	$(RM) -f core $(EXE)

bin/sealtool: src/*.hpp src/*.cpp
	@if [ ! -d "bin" ] ; then mkdir bin ; fi
	$(CXX) $(CXXFLAGS) $(OPTS) $(INC) -o $@ $^ $(LIB)
	@if [ "$(STRIP)" != "" ] ; then $(STRIP) $@ ; fi

# I need libcurl using openssl 3.x
# Ubuntu 20.04 uses openssl with 1.x
libcurl:
	rm -rf curl-8.10.1
	wget -O curl-8.10.1.tar.gz 'https://curl.se/download/curl-8.10.1.tar.gz'
	tar -xzvf curl-8.10.1.tar.gz
	(cd curl-8.10.1 ; LDFLAGS=-L/usr/local/lib64 ./configure --with-openssl)
	(cd curl-8.10.1 ; make -j 4)


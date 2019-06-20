# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

prefix = /usr/local

INCLUDES = -I/usr/include/x86_64-linux-gnu/curl -I. -I.. -Iext -I../Linux/ext/intel
CFLAGS = -fPIC -std=c++14 -Wall -Werror $(INCLUDES) -D__LINUX__ -Wno-unknown-pragmas -pthread

PROVIDER_SRC = ../dcap_provider.cpp ../curl_easy.cpp local_cache.cpp init.cpp
PROVIDER_OBJ = $(PROVIDER_SRC:.cpp=.o)
PROVIDER_LIB = libdcap_quoteprov.so # this name is dictated by Intel
PROVIDER_LDFLAGS = -shared $(shell curl-config --libs) `pkg-config --libs openssl`

TEST_SUITE = tests
TEST_SUITE_SRC = ../UnitTests/main.cpp
TEST_SUITE_SRC += ../UnitTests/test_local_cache.cpp
TEST_SUITE_SRC += ../UnitTests/test_quote_prov.cpp
TEST_SUITE_SRC += local_cache.cpp
TEST_SUITE_OBJ = $(TEST_SUITE_SRC:.cpp=.o)
TEST_SUITE_LDFLAGS = -ldl `pkg-config --libs openssl`

.cpp.o:
	g++ $(CFLAGS) -c $< -o $@

$(PROVIDER_LIB): $(PROVIDER_OBJ)
	g++ $^ $(PROVIDER_LDFLAGS) -o $@

$(TEST_SUITE): $(PROVIDER_LIB) $(TEST_SUITE_OBJ)
	g++ $(CFLAGS) $(TEST_SUITE_OBJ) $(TEST_SUITE_LDFLAGS) -o $@

all: $(PROVIDER_LIB)

clean:
	rm -rf $(PROVIDER_OBJ) $(PROVIDER_LIB) $(TEST_SUITE_OBJ) $(TEST_SUITE)

check: $(TEST_SUITE)
	LD_LIBRARY_PATH=`dirname $(PROVIDER_LIB)` ./$(TEST_SUITE)

distclean: clean

install:
	install -D $(PROVIDER_LIB) $(DESTDIR)$(prefix)/lib/$(PROVIDER_LIB)
	install -D ../dcap_provider.h $(DESTDIR)$(prefix)/include/dcap_provider.h

uninstall:
	rm -f $(DESTDIR)$(prefix)/lib/$(PROVIDER_LIB)
	rm -f $(DESTDIR)$(prefix)/include/dcap_provider.h

.PHONY: all install clean distclean uninstall

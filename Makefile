# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CC=clang++
CFLAGS=-Ipkix/include -I/usr/include/nspr4/ -I/usr/include/nss3 -g -Wall -c -std=c++11
LDFLAGS=-lnss3 -lnssutil3 -lnspr4
SOURCES=pkix/lib/pkixbind.cpp pkix/lib/pkixbuild.cpp pkix/lib/pkixcheck.cpp \
        pkix/lib/pkixder.cpp pkix/lib/pkixkey.cpp pkix/lib/pkixocsp.cpp \
				ev-checker.cpp \
				EVCheckerTrustDomain.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=ev-checker

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

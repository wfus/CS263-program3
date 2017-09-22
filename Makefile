# You may change anything in this file except the test-related rules.
#
# In fact, you will almost definitely need to change some of the compilation
# rules to make the linker happy.


CFLAGS=-std=gnu11 -O2 -Wall

NOSEFLAGS=-v -s

.PHONY: all
all: sniffer rst_http hijack_telnet

.PHONY: clean
clean:
	rm -f sniffer rst_http hijack_telnet

sniffer: sniffer.h sniffer.c
	gcc $(CFLAGS) -o sniffer sniffer.c

rst_http: sniffer.h rst_http.c
	gcc $(CFLAGS) -o rst_http rst_http.c

hijack_telnet: sniffer.h hijack_telnet.c
	gcc $(CFLAGS) -o hijack_telnet hijack_telnet.c


# Do NOT change anything below!

.PHONY: test
test: assert_pyvers assert_nose sniffer rst_http hijack_telnet
	sudo python3 -m nose $(NOSEFLAGS) tests/tests.py

.PHONY: test_sniffer
test_sniffer: assert_pyvers assert_nose sniffer
	sudo python3 -m nose $(NOSEFLAGS) \
		tests/tests.py:test_sniffer_icmp \
		tests/tests.py:test_sniffer_tcp \
		tests/tests.py:test_sniffer_udp

.PHONY: test_rst_http
test_rst_http: assert_pyvers assert_nose rst_http
	sudo python3 -m nose $(NOSEFLAGS) tests/tests.py:test_rst_http

.PHONY: test_hijack_telnet
test_hijack_telnet: assert_pyvers assert_nose hijack_telnet
	sudo python3 -m nose $(NOSEFLAGS) tests/tests.py:test_hijack_telnet

.PHONY: assert_pyvers
assert_pyvers:
	sudo python3 -c 'import sys; assert sys.version_info[1] >= 4'

.PHONY: assert_nose
assert_nose:
	sudo python3 -c 'import nose'

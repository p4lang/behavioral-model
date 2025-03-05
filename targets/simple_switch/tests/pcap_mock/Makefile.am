AM_CXXFLAGS = -g -pthread -std=c++20
AM_LDFLAGS = -L.
LDLIBS = -lpcap

bin_PROGRAMS = test_pcap
lib_LIBRARIES = libpcap.a

libpcap_a_SOURCES = mock_libpcap.cpp pcap_mock.hpp

libpcap_a_LIBADD = 

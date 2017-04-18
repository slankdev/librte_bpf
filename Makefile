
LIB = /home/slank/git/libslankdev
CXXFLAGS = -std=c++11 -I$(LIB) -Wno-format-security

all:
	$(CXX) $(CXXFLAGS) main.cc -lpcap -lcapstone

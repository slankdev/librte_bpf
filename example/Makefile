

LIB = ../
CXX = g++
CXXFLAGS = -std=c++11 -I$(LIB)
LDFLAGS  = -lpcap -lcapstone

SRC = \
			hello.cc
OBJ = $(SRC:.cc=.out)


.cc.out:
	@echo "CXX $@"
	@$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

def: $(OBJ)
clean:
	rm -rf $(OBJ)

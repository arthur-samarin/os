all: rshd
%.o: %.cpp
	g++ -std=c++14 -c $< -o $@
rshd: rshd.o
	g++ -s $^ -o $@
clean:
	rm -f *.o rshd

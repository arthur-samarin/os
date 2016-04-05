all: midtermsh
%.o: %.cpp
	g++ -std=c++11 -c $< -o $@
midtermsh: midtermsh.o
	g++ -s $^ -o $@
clean:
	rm -f *.o midtermsh

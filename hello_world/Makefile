all: hello_world
%.o: %.c
	gcc -c $< -o $@
hello_world: hello_world.o
	gcc -s $^ -o $@
clean:
	rm *.o hello_world

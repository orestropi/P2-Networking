
all:wireview.o
	g++ -lpcap -o wireview wireview.cpp
	
clean:
	$(RM) wireview

all:wireview.o
	g++ wireview.cpp -o wireview -lpcap

clean:
	$(RM) wireview
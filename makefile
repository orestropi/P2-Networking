
all:wireview.o wireviewProofOfCorrectParsing.o
	g++ wireview.cpp -o wireview -lpcap
	g++ wireviewProofOfCorrectParsing.cpp -o wireviewProofOfCorrectParsing -lpcap

clean:
	$(RM) wireview wireview.o wireviewProofOfCorrectParsing wireviewProofOfCorrectParsing.o
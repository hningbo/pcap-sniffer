main:Sniffer.o main.o
	g++ -o main Sniffer.o main.o -l pcap

Sniffer.o:Sniffer.cpp Sniffer.h
	g++ -c Sniffer.cpp -l pcap

main.o:main.cpp Sniffer.h
	g++ -c main.cpp -l pcap

clean:
	rm main main.o Sniffer.o

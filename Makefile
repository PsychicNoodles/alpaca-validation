

all: alpaca_no2.cc
	g++ -shared -fPIC -o alpaca_no2.so alpaca_no2.cc -ldl

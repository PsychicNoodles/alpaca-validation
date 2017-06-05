

all: alpaca_no2.cc
	g++ -g -rdynamic -shared -fPIC -o alpaca_no2.so alpaca_no2.cc -ldl

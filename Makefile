

all: alpaca_no2.cc
	clang++ -g --std=c++11 -rdynamic -shared -fPIC -o alpaca_no2.so alpaca_no2.cc -ldl -ludis86
	clang -g example.c -o example

run:
	LD_PRELOAD=./alpaca_no2.so:libelf++.so:libudis86.so example fake_func

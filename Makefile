all: alpaca_no2.cc
	clang++ -g --std=c++11 -rdynamic -shared -fPIC -o alpaca_no2.so alpaca_no2.cc -ldl -ludis86
	clang -g example.c -o example
	clang -g prime-test.c -o prime-test

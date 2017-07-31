all: alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc
	clang++ alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc -g --std=c++11 -rdynamic -shared -fPIC -o alpaca.so -ldl -ludis86

nolog: alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc
	clang++ -D NDEBUG alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc -g --std=c++11 -rdynamic -shared -fPIC -o alpaca.so -ldl -ludis86

minlog: alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc
	clang++ -D MINDEBUG alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc -g --std=c++11 -rdynamic -shared -fPIC -o alpaca.so -ldl -ludis86

check: all
	clang test-suite.c -g -O3 -femulated-tls -static-libgcc -o test-suite
	python run-tests.py

all: alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc
	clang++ alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc -g --std=c++11 -mcmodel=large -rdynamic -shared -fPIC -o alpaca.so -ldl -ludis86

nolog: alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc
	clang++ -D NDEBUG alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc -g --std=c++11 -mcmodel=large -rdynamic -shared -fPIC -o alpaca.so -ldl -ludis86

minlog: alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc
	clang++ -D MINDEBUG alpaca_shared.cc alpaca_no2.cc alpaca_fn_disabler.cc -g --std=c++11 -mcmodel=large -rdynamic -shared -fPIC -o alpaca.so -ldl -ludis86

check: all
	clang test-suite.c -g -o test-suite
	python run-tests.py

energy: energy.cpp
	clang++ --std=c++11 energy.cpp -g -o energy

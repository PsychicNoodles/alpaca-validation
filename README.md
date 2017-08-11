# Alpaca Validation (aka Alpaca v2)

This repository contains the Alpaca Validation tool, or Alpaca v2. Alpaca
is a profiler that measures the energy consumption of a program's
individual functions.

You can find the original Alpaca
[here](https://github.com/grinnell-cs/alpaca).

## Prerequisites

There are two libraries used by this program:
[udis86](http://udis86.sourceforge.net/) and
[libelfin](https://github.com/aclements/libelfin). One is included
(libelfin), but you must install udis86 either with your package manager or
by downloading it and following [the installation guide](
http://udis86.sourceforge.net/manual/getstarted.html#building-and-installing-udis86).

Additionally, Intel's RAPL energy interface is used by the `energy` utility
program for measurements.

## How does it work?

The idea behind Alpaca v2 is to find and turn off a particular function in
order to see how much energy a program will consume without
it. Practically, this is done by analyzing the function to determine
the key actions it performs, like writes to the heap and return value, and
then replicating those actions when the function is disabled. Ideally, when
run on good target functions, especially those that have more computation
than storage, the energy usage will go down due to many unnecessary
instructions being skipped.

The goal of Alpaca v2 is not to optimize or directly reduce the energy
usage of a program. Instead, it is simply a tool that can help you narrow
down what parts of your program are problematic and need improving.

## But how does it actually work?

The flow of Alpaca v2 (exact order differs slightly from the code to help
understandability) is as follows. For the analyzer:

* Find the function by looking at the elf components of the target binary.

* Set the first byte of the function to `0xCC`, which is an `int3`
  instruction which causes a `SIGTRAP` signal to be sent.

* Set a handler for the `SIGTRAP` signal, then start the program and wait
  for the function to be called.

* If the first byte was `0x55` we know that's a `push %rbp` so we can just
  simulate that effect ourselves. Otherwise, put back the original byte and
  move the instruction pointer, `RIP`, back one so that the original first
  instruction can be properly executed.

* Once the function has been naturally called by the program, set the
  `TRAP` EFL flag, which causes a `SIGTRAP` to be sent on every
  instruction, and continue doing so until the function is done.

* Every time the trap handler is called, disassemble the current
  instruction and determine what to do with it. Except for special cases
  (see below), we categorize instructions as either read-only or
  potential write. Read-only means it doesn't affect memory, meaning it
  only touches registers or flags (ex. `push`, `pop`, any jumps). Potential
  write means it might touch memory (ex. `inc`, `mov`, `neg`).

  * `call` and `ret`/`retf` are special cases as they indicate the function
    is going into another function. The position in this function stack
    must be kept track of so that you know when the target function is
    about to exit. As such, a counter is incremented and decremented on
    `call` and `ret`, respectively.

  * Syscalls are important to note because they cut up each function
    invokation a bit. Changes to global state can typically be managed
    since every instruction is disassembled and analyzed, but syscalls are
    an anomaly in that they involve kernal state that we have no access to
    in userland. See [the section below](#syscalls) for more details on how exactly
    syscalls are handled.

  * Udis86, the disassembly library used, is a bit limited in recognized
    x86 instructions. In many use cases this is not an issue, but
    unfortunately there are certain weird instructions out there,
    especially in use by libc which presumably has to support any unusual
    standards that are invented, such as Intel MPX and AVX. For some of
    these instructions that are common, we simply do our own disassembly by
    manipulating udis a little bit. See [the section
    below](#weird-instruction-sets) for more details on weird instruction
    sets.

* When a potential write instruction is detected, we check to see what its
  destination is. If it's in memory, then we compare it with the stack
  frame, which is from the `RSP` when the function was first called to the
  current `RSP` minus 128 bytes for the ["red
  zone"](https://en.wikipedia.org/wiki/Red_zone_(computing)). If it's in
  the stack frame we ignore it since stack state gets thrown out at the end of
  the function invokation anyway (the stack matters a bit for [syscalls,
  though](#syscalls). However, if it's not in the stack frame then we
  record the destination address to be saved after the next
  instruction. We wait for the next instruction since the disassembled
  instruction, which comes from the `RIP`, has not actually been executed
  yet; it's about to be, so we just need to wait until the next instruction
  and then its effects will be complete.

* On the next instruction, before disassembling if there was a write on the
  last instruction then we save the value at its destination. See [the
  section below](#data-format) for details on how exactly the logged values
  are stored.

* If we've hit the end of the target function, save the return value. This
  is done by checking which of the registers associated with return values
  (`RAX`, `RDX`, `XMM0`, and `XMM1) have been touched.

This is quite a bit that needs to be done, but that's because every single
thing the target function does needs to be analyzed to see if it's
noteworthy. Luckily, the disabler is significantly simpler, though you have
to be careful about how you do it, and reuses some components:

* Find the function again.

* Read in all the data recorded by the analyzer.

* Set the first byte of the function to be a jump to our own special
  disabler function.

* Sequentially mimic the effects of writes and syscalls by directly setting
  values in memory (see [the section below](#syscalls) for more details on
  how syscalls are done).

There are a number of nuances in disabling a function, especially since
we're directly messing with registers and touching memory that might get
mapped by the function we're disabling, and the process to getting the
current working version took some time but conceptually it's very straightforward.

## Building

There are three main make targets for building everything and one target for
testing basic functionality.

* You can build Alpaca v2 with `make`, optionally turning off levels of
debug info (which goes to `stderr`) with the `make minlog` and `make nolog`
targets (these targets define the `NDEBUG` and `MINDEBUG` preprocessor variables, respectively).


* The test suite, which contains small functions with various method calls,
  like `malloc`, and return types can be built with the `make test-suite`
  target.

* The energy utilty, which runs both the analyzer and the disabler and
  measures the energy consumption of the latter, can be built with the
  `make energy` target.

* Everything can be put together with the `make check`
  target, which builds it all and executes the `run-tests.py` script, running
  both the analyzer and disabler and verifying the output of the latter.

## Running

Alpaca v2 is run by preloading it via `LD_PRELOAD`, and its parameters are
passed via environment variables:

* `ALPACA_MODE`: either `a` or `d` for analyze or disable mode.

* `ALPACA_FUNC`: the function to analyze/disable

* `ALPACA_PPID`: the PID of the parent process to send signals when you
  want energy measured (see [the section below](#energy-signals) for more
  details on how these signals are used), can be an invalid PID (which just
  causes the signals to not be sent)

A fun sidenote about environment variables is that they actually take up
stack space above the main. This means that if all the environment
variables are not the same length in both the analyzer and disabler they
could potentially make it uneven and break everything (see [the section
below](#memory-issues) for more details on things that can destroy Alpaca
v2).

## Details

### Syscalls

Syscalls affect state that the user, even with lower level access like in
Alpaca v2, cannot see. As such, the simplest way to deal with syscalls is
to simply check what it needs as parameters and what it returns at the end
and simulate both.

Most syscalls take at least some sort of parameter. Many, like `mmap` and
`mprotect`, only use numbers, so as long as all the parameter registers'
values are saved and replicated there's no issue. However, some syscalls,
like `open` and `stat`, want a buffer and read and/or write to it. If we
only save the value of the pointer then when the syscall tries to use it it
might look at memory used by something else or that just isn't mapped which
can cause anything from prints mysteriously changing to immediate
segfaults. The way to solve this problem is by finding the chunk of memory
that is used by the syscall, the size of which is generally provided
through other registers and/or constants, and saving it.

Additionally, the return value of the syscall is verified to make sure
everything is going as expected. This is helpful both for syscalls that
just return 0 when it succeeds, since you know that the syscall in the
disabler also worked, or when it returns something special like the pointer
return value from `mmap`. For `mmap` in particular, if the return value is
different then that means the program used a different number of `mmap`s
previously, since it automatically gives you memory based on previous
calls. This means [you can't use C++ structures since they often use
`malloc` under the hood](#memory-issues).

### Weird Instruction Sets

There are a couple newer instruction sets that aren't universally
recognized, in particular by udis, which means that they're a pain to
handle. 

#### Intel MPX

MPX instructions are [neat in theory](https://intel-mpx.github.io/), but
apparently too rare for udis to support. Thankfully, not too many of them
are used by libc and the conversion process to the non-MPX versions is not
too bad. Typically it involves removing the prefix and then switching the
opcode over, but the parameters are often the same.

MPX is actually supported by another disassembly library called
[diStorm](https://github.com/gdabah/distorm), but switching over takes time
and is not guaranteed to be perfectly compatible.

#### AVX

AVX instructions are for [vector-related
computations](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions). They're
generally not too bad, but the biggest potential issue with AVX is when it
tries to use `ymm` registers. Udis, unsurpisingly, also doesn't support
these registers so it can't help in any way when these instructions come
along. Thankfully, moves from `ymm` registers seem to only go to registers
and not memory, so they can be ignored.

### Energy Signals

Since the energy utility lives in its own process, there needs to be an
inter-process way of communicating that Alpaca v2 needs energy
measurements. The way this is done is by sending the energy process the
`SIGUSR1` signal, which causes it to take a snapshot of energy readings. It
will continue to do this as many times as it receives this signal until the
analyzer and disabler processes exit, and at the end it will provide diffs
of each reading in case you want to take more than two readings.

### Memory Issues

Since direct memory values are recorded by the analyzer and have to be
replayed by the disabler, the heap in Alpaca v2 is very
sensitive to even the most minor adjustents. Since every time you call
`mmap` you receive a new block of memory based on how many times it's
already been called, if something in Alpaca v2 causes a `mmap` then
everything after may be shifted over, which obviously can cause some
serious issues. C++ collections, while convenient, often use `malloc` under
the hood which means that they are not usable. As such, stack array-based
"queues" are used throughout the analyzer and disabler.

The downside to this stack based storage is that the full capacity must be
allocated in memory no matter how small the program. This generally isn't a
huge issue, but on machines that have little memory it could theoretically
slow things down a bit.

### Data Format

The information about writes, return values, and syscall parameters and return
values are stored as raw bytes in a structured
sequence in the `write-logger`, `return-logger`, and `sys-logger`, respectively. Each value logger is as an 8-byte
value unless described otherwise.

* Writes are stored as pairs of the destination address and the value.

* Syscalls are stored as sequences of the syscall number and each
  parameter, with the number of parameters depending on the syscall number.

* Each return delimits a sequence of writes/syscalls, which allows
  distinguishing between the writes/syscalls from one function invokation
  and the next. First, the number of writes/syscalls, then a
  flag with that number of bits with 1 meaning a write and 0
  meaning a syscall (zero padded to fill out the last byte). Then, a flag
  where each bit is associated with a return register (`RAX`, `RDX`,
  `XMM0`, and `XMM1`) with 1 meaning it was touched and 0 meaning it
  wasn't. Finally, for each register that was touched if it is an integer
  register (`RAX` and `RDX`) then the 8-byte value is written while if it
  is a floating point register (`XMM0` and `XMM1`) then 4 4-byte values are written.

## Contributors

This project was made possible through the blood, sweat, and tears of
[Mattori Birnbaum](https://github.com/PsychicNoodles), [Marija
Ivica](https://github.com/maripot), and [Sara
Marku](https://github.com/saramarku) under the guidance of our research
advisor [Charlie Curtsinger](https://github.com/ccurtsinger) in Summer 2017
at [Grinnell College](http://www.grinnell.edu).

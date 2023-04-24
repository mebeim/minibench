Minibench
=========

Minimalistic runtime benchmarking utility for Linux written in plain C99.

<p align="center"><img title="Screenshot" src="screenshot.png"></img></p>

Design goals:

- Concise, well documented, standard-conforming code.
- No external dependencies of any kind.
- Smallest possible overhead (within reasonable limits) for the timing code.
- Ability to perform warm-up runs before starting timed runs.
- Calculation of total, median, average, standard deviation, minimum and maximum
  of wall-clock time and CPU time, using an online algorithm where possible
  (i.e. for everything except median).
- Preservation of the exit status of the benchmarked program when possible.
- Ability to mute the benchmarked program's output (stdout and stderr).
- Ability to early stop a running benchmarking session through CTRL+C (SIGINT).
- Human readable, pretty-printed output.

Building and installation
-------------------------

Minibench is designed to run on a Linux system, though it will probably also
compile and run on other Unix-like systems.

Use `make` to build, `make install` to install, and `make uninstall` to
uninstall. Installing will simply create a copy of the compiled `bench` binary
inside `~/.local/bin/`, so make sure that directory is in your `PATH`.

Usage
-----

Invoke `bench -h` for usage information:

```
Usage: bench [-hkqQv] [-n COUNT] [-w COUNT] PROGRAM [ARGS...]
Benchmark the running time of PROGRAM invoked with the given ARGS.

Command line options:
  -n COUNT  number of runs of the benchmarked program
  -w COUNT  number of warm-up runs of the benchmarked program before timed runs
  -k        forcibly kill benchmarked program if stopped by a signal, instead of
            waiting for it to continue (default behavior)
  -q        mute benchmarked program redirecting its stdout/stderr to /dev/null
  -Q        forcibly mute benchmarked program closing its stdout/stderr
  -h        show this help message and exit
  -v        print version information and exit

The exit status will be the one of the benchmarked program's last run, unless
stopped or killed by a signal, in which case it will be 128 + signal number.
On error, an error message will be printed before exiting with status 1.
```

---

*Copyright &copy; 2022 Marco Bonelli. Licensed under the Apache License v2.0.*

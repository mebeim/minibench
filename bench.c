/**
 * Minimalistic runtime benchmarking utility for Linux.
 *
 * Copyright 2022 Marco Bonelli
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _DEFAULT_SOURCE         // wait4
#define _POSIX_C_SOURCE 200809L // clock_gettime, strsignal
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>

#define VERSION_STR "1.1.1"

// Wrap the real function passing caller line number as argument in order to be
// able to track down errors
#define restore_stderr() restore_stderr_track_caller(__LINE__)

#define err(str)            do { restore_stderr(); fprintf(stderr, "%s: " str, name); } while(0)
#define errf(fmt, ...)      do { restore_stderr(); fprintf(stderr, "%s: " fmt, name, __VA_ARGS__); } while(0)
#define err_exit(str)       do { restore_stderr(); fprintf(stderr, "%s: " str, name); exit(EXIT_FAILURE); } while(0)
#define errf_exit(fmt, ...) do { restore_stderr(); fprintf(stderr, "%s: " fmt, name, __VA_ARGS__); exit(EXIT_FAILURE); } while(0)

// Max number of warnings to print for child termination/stop by signal
#define MAX_CHILD_WARNINGS 3

// Max number of measurements we are willing to hold in memory in order to be
// able to calculate a median (1M measurements is 32MB)
#define MAX_MEASUREMENTS (1 * 1000 * 1000)

struct running_stats {
	double tot;
	double min;
	double max;
	double avg;
	double m2;
	double *hist;
};

static char *name;
static pid_t child_pid;
static unsigned child_warnings;
static unsigned long count = 1;
static unsigned long wup_count;
static int saved_stderr = -1;

static struct running_stats wall_stats     = {.min = INFINITY, .max = -INFINITY};
static struct running_stats cpu_stats      = {.min = INFINITY, .max = -INFINITY};
static struct running_stats cpu_user_stats = {.min = INFINITY, .max = -INFINITY};
static struct running_stats cpu_sys_stats  = {.min = INFINITY, .max = -INFINITY};

/**
 * Print version information and exit.
 */
static void version_exit(void) {
	printf("Minibench version %s\n", VERSION_STR);
	puts("Copyright (C) 2022 Marco Bonelli");
	puts("Licensed under the Apache License v2.0");
	exit(EXIT_SUCCESS);
}

/**
 * Print full help and exit.
 */
static void help_exit(void) {
	printf("Usage: %s [-hkqQv] [-n COUNT] [-w COUNT] PROGRAM [ARGS...]\n", name);
	puts("Benchmark the running time of PROGRAM invoked with the given ARGS.\n");
	puts(
		"Command line options:\n"
		"  -n COUNT  number of runs of the benchmarked program\n"
		"  -w COUNT  number of warm-up runs of the benchmarked program before timed runs\n"
		"  -k        keep benchmarked program alive if stopped by a signal, instead of\n"
		"            forcibly killing it (which is the default behavior)\n"
		"  -q        mute benchmarked program redirecting its stdout/stderr to /dev/null\n"
		"  -Q        forcibly mute benchmarked program closing its stdout/stderr\n"
		"  -h        show this help message and exit\n"
		"  -v        print version information and exit\n"
	);
	puts(
		"Exit status will be the one of the benchmarked program's last run, unless\n"
		"stopped or killed by a signal, in which case the exit status is 0."
	);
	printf("On error, an error message is printed before exiting with status %d.\n\n", EXIT_FAILURE);
	exit(EXIT_SUCCESS);
}

/**
 * Print brief usage information and exit.
 */
static void usage_exit(const char *msg) {
	if (msg)
		fputs(msg, stderr);

	fprintf(stderr, "Usage: %s [-hkqQv] [-n COUNT] [-w COUNT] PROGRAM [ARGS...]\n", name);
	fprintf(stderr, "See '%s -h' for more information.\n", name);
	exit(EXIT_FAILURE);
}

/**
 * Parse a number using strtol and ensure its value is >= 1, exiting in case of
 * parsing error or invalid value.
 */
static unsigned long validate_count(const char *s) {
	char *endp;
	long count;

	count = strtol(s, &endp, 0);

	if (endp == s || *endp)
		usage_exit("invalid count: not an integer\n");
	if (errno == ERANGE)
		usage_exit("invalid count: value too large\n");
	if (count < 1)
		usage_exit("invalid count: value must be positive\n");

	return (unsigned long)count;
}

/**
 * Convert and print nanoseconds in human-readable form.
 */
static void pptime(const double nsecs) {
	if      (nsecs <  5e-4) { fputs("      0  ", stderr);              }
	else if (nsecs <  1e3 ) { fprintf(stderr, "%7.3fns", nsecs);       }
	else if (nsecs <  1e6 ) { fprintf(stderr, "%7.3fus", nsecs / 1e3); }
	else if (nsecs <  1e9 ) { fprintf(stderr, "%7.3fms", nsecs / 1e6); }
	else                    { fprintf(stderr, "%7.3fs ", nsecs / 1e9); }
}

/**
 * Update a single category of running statistics using Welford's online
 * algorithm.
 *
 * NOTE: The textbook approach of calculting the variance as a sum of squared
 * differences from the average is not very accurate with floating point values
 * due to classic floating point math shenanigans. A more accurate result could
 * be obtained transforming each double into an integer fraction and then
 * working on numerators and denominators separately as integers (this is how
 * e.g. Python's statistics.variance() works). Alternatively uint64_t could be
 * used everywhere instead of double taking appropriate measures to avoid
 * overflows. I am nonetheless happy as is. Standard deviation is not really a
 * critical statistic.
 *
 */
static void update_stats_single(struct running_stats *stats, const unsigned long iteration, const double cur) {
	const double delta = cur - stats->avg;

	stats->avg += delta / (iteration + 1);
	stats->m2  += delta * (cur - stats->avg);
	stats->tot += cur;

	if (cur < stats->min)
		stats->min = cur;
	if (cur > stats->max)
		stats->max = cur;
	if (stats->hist)
		stats->hist[iteration] = cur;
}

/**
 * Update all running statistics and save measurements for later calculation if
 * needed.
 */
static void update_stats(const unsigned long iteration, const double wall, const double cpu_user, const double cpu_sys) {
	const double cpu = cpu_user + cpu_sys;
	update_stats_single(&wall_stats    , iteration, wall);
	update_stats_single(&cpu_stats     , iteration, cpu);
	update_stats_single(&cpu_user_stats, iteration, cpu_user);
	update_stats_single(&cpu_sys_stats , iteration, cpu_sys);
}

/**
 * Compare function for qsort.
 */
static int cmp(const void *a, const void *b) {
	const double da = *(const double *)a;
	const double db = *(const double *)b;
	return (da > db) - (da < db);
}

/**
 * Finalize statistics with appropriate calculations and pretty-print a detailed
 * timing report.
 */
static void timing_report(void) {
	double wall_std, cpu_std, cpu_user_std, cpu_sys_std;

	// Always output a leading newline (\n) to avoid bad-looking output if the
	// benchmarked program did not end its last line of output with a newline

	if (count == 1) {
		fputs("\n------------------------------------------------\n", stderr);
		fputs("         Wall        CPU       User     System\nTime  ", stderr);
		pptime(wall_stats.tot);     fputs("  ", stderr);
		pptime(cpu_stats.tot);      fputs("  ", stderr);
		pptime(cpu_user_stats.tot); fputs("  ", stderr);
		pptime(cpu_sys_stats.tot);  fputc('\n', stderr);
		return;
	}

	fprintf(stderr, "\n-----------[ Timing report for %ld runs ]------------\n", count);
	fputs("            Wall        CPU       User     System\nTotal    ", stderr);
	pptime(wall_stats.tot);     fputs("  ", stderr);
	pptime(cpu_stats.tot);      fputs("  ", stderr);
	pptime(cpu_user_stats.tot); fputs("  ", stderr);
	pptime(cpu_sys_stats.tot);  fputc('\n', stderr);

	wall_std     = sqrt(wall_stats.m2 / count);
	cpu_std      = sqrt(cpu_stats.m2 / count);
	cpu_user_std = sqrt(cpu_user_stats.m2 / count);
	cpu_sys_std  = sqrt(cpu_sys_stats.m2 / count);

	if (wall_stats.hist) {
		const unsigned long mid = count / 2;
		double wall_mid, cpu_mid, cpu_user_mid, cpu_sys_mid;

		// It's possible to find the median in linear time without sorting using
		// quickselect, but for reasonable values of count (<= 1M) it's just not
		// worth the effort to implement that.
		qsort(wall_stats.hist    , count, sizeof(*wall_stats.hist)    , cmp);
		qsort(cpu_stats.hist     , count, sizeof(*cpu_stats.hist)     , cmp);
		qsort(cpu_user_stats.hist, count, sizeof(*cpu_user_stats.hist), cmp);
		qsort(cpu_sys_stats.hist , count, sizeof(*cpu_sys_stats.hist) , cmp);

		if (count % 2) {
			wall_mid     = wall_stats.hist[mid];
			cpu_mid      = cpu_stats.hist[mid];
			cpu_user_mid = cpu_user_stats.hist[mid];
			cpu_sys_mid  = cpu_sys_stats.hist[mid];
		} else {
			wall_mid     = (wall_stats.hist[mid - 1] + wall_stats.hist[mid]) / 2;
			cpu_mid      = (cpu_stats.hist[mid - 1] + cpu_stats.hist[mid]) / 2;
			cpu_user_mid = (cpu_user_stats.hist[mid - 1] + cpu_user_stats.hist[mid]) / 2;
			cpu_sys_mid  = (cpu_sys_stats.hist[mid - 1] + cpu_sys_stats.hist[mid]) / 2;
		}

		fputs("Median   ", stderr);
		pptime(wall_mid);     fputs("  ", stderr);
		pptime(cpu_mid);      fputs("  ", stderr);
		pptime(cpu_user_mid); fputs("  ", stderr);
		pptime(cpu_sys_mid);  fputc('\n', stderr);
	}

	fputs("Average  ", stderr);
	pptime(wall_stats.avg);     fputs("  ", stderr);
	pptime(cpu_stats.avg);      fputs("  ", stderr);
	pptime(cpu_user_stats.avg); fputs("  ", stderr);
	pptime(cpu_sys_stats.avg);  fputc('\n', stderr);

	fputs("Std dev  ", stderr);
	pptime(wall_std);     fputs("  ", stderr);
	pptime(cpu_std);      fputs("  ", stderr);
	pptime(cpu_user_std); fputs("  ", stderr);
	pptime(cpu_sys_std);  fputc('\n', stderr);

	fputs("Minimum  ", stderr);
	pptime(wall_stats.min);     fputs("  ", stderr);
	pptime(cpu_stats.min);      fputs("  ", stderr);
	pptime(cpu_user_stats.min); fputs("  ", stderr);
	pptime(cpu_sys_stats.min);  fputc('\n', stderr);

	fputs("Maximum  ", stderr);
	pptime(wall_stats.max);     fputs("  ", stderr);
	pptime(cpu_stats.max);      fputs("  ", stderr);
	pptime(cpu_user_stats.max); fputs("  ", stderr);
	pptime(cpu_sys_stats.max);  fputc('\n', stderr);
}

/**
 * Restore previously duped stderr file descriptor to STDERR_FILENO if needed.
 */
static void restore_stderr_track_caller(int caller_lineno) {
	if (saved_stderr == -1)
		return;

	if (dup2(saved_stderr, STDERR_FILENO) == -1) {
		const char *fmt = ": unable to restore stderr (line %d): %s\n";
		char msg[256] = {0};

		snprintf(msg, sizeof(msg), fmt, caller_lineno, strerror(errno));
		write(saved_stderr, name, strlen(name));
		write(saved_stderr, msg, strlen(msg));
		exit(EXIT_FAILURE);
	}
}

/**
 * Redirect stdout and stderr to /dev/null in order to mute the child process.
 * Duplicate and save stderr on the first call to be able to restore it later.
 */
static void redirect_to_devnull(void) {
	static int devnull_fd = INT_MIN;

	// This seemingly weird juggling of file descriptors is useful to avoid any
	// syscall between fork and exec. We will exec the child with stdout and
	// stderr already pointing to /dev/null. Any other unneeded file descriptor
	// will have CLOEXEC set and will be wiped out on exec.

	if (devnull_fd == INT_MIN) {
		devnull_fd = open("/dev/null", O_WRONLY|O_CLOEXEC);
		if (devnull_fd == -1) {
			errf("unable to open /dev/null: %s\n", strerror(errno));
			err("child process stdout/stderr will not be redirected\n");
			return;
		}

		// No need to save stdout as we will only write to stderr from now on
		dup2(devnull_fd, STDOUT_FILENO);

		// Save stderr to restore it later if needed, do not error out in case
		// of failure as we are merely trying to accomodate the user
		if ((saved_stderr = dup(STDERR_FILENO)) != -1)
			fcntl(saved_stderr, F_SETFD, FD_CLOEXEC);
	}

	// Only mute stderr if we were able to save it, or we will completely lose
	// the ability to produce output
	if (saved_stderr != -1)
		dup2(devnull_fd, STDERR_FILENO);
}

/**
 * Set up file descriptors so that the child process will be muted. There can be
 * two levels: 1 = redirect child stdout and stderr to /dev/null; 2 = close
 * child stdout and stderr setting FD_CLOEXEC on them in the parent.
 */
static void mute_child(unsigned level) {
	static bool cloexec_done = false;

	// This will need to be done once before each run, because we could have
	// restored stderr for printing a warning between any two runs
	if (level == 1) {
		redirect_to_devnull();
		return;
	}

	// This only needs to be done once as it's persistent
	if (!cloexec_done && level == 2) {
		if (fcntl(STDOUT_FILENO, F_SETFD, FD_CLOEXEC) == -1)
			errf("unable to close stdout for child process: %s\n", strerror(errno));
		if (fcntl(STDERR_FILENO, F_SETFD, FD_CLOEXEC) == -1)
			errf("unable to close stderr for child process: %s\n", strerror(errno));

		cloexec_done = true;
	}
}

/**
 * Create a pipe for the child process to report execve failure and set
 * FD_CLOEXEC on both ends so that they are automatically closed on successful
 * execve.
 */
static void create_pipe(int *fds) {
	if (pipe(fds) == -1)
		errf_exit("pipe failed: %s\n", strerror(errno));
	if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) == -1)
		errf_exit("fcntl on read end of pipe failed: %s\n", strerror(errno));
	if (fcntl(fds[1], F_SETFD, FD_CLOEXEC) == -1)
		errf_exit("fcntl on write end of pipe failed: %s\n", strerror(errno));
}

/**
 * Run child program once, report exit status and resource usage if needed,
 * communicate errno to the parent on execve failure. This function should do
 * the least amount of work possible before forking and after waiting for the
 * child in order to minimize delays in time measurements.
 */
inline static int run_child(char *const *argv, const int err_pipe_fd, struct rusage *rusage) {
	int child_status;

	child_pid = fork();

	if (child_pid == 0) {
		execvp(*argv, argv);

		// We need to communicate failure to the parent in order to abort
		// execution, but we cannot just exit with a custom error code,
		// otherwise any child process that actually uses such code would create
		// a false positive. Furthermore, we can't print anything here since the
		// above dup2 calls could point std{out,err} to /dev/null. Using a pipe
		// is a neat and reliable way of solving the problem.
		write(err_pipe_fd, &errno, sizeof(errno));
		_exit(EXIT_FAILURE);
	}

	if (child_pid == -1)
		errf_exit("fork failed: %s\n", strerror(errno));

	// Prefer wait4 to wait + clock_gettime(CLOCK_PROCESS_CPUTIME_ID)
	if (wait4(child_pid, &child_status, WUNTRACED, rusage) == -1)
		errf_exit("wait4 failed: %s\n", strerror(errno));

	// Delay child status checking to the caller to avoid wasting time before
	// querying the wall clock
	return child_status;
}

/**
 * Check child exit status, warn and forcibly kill child if needed, close both
 * ends of the pipe used by the child to report execve failure.
 */
static void check_child_exit(const int child_status, const int *child_pipe, bool keep_alive) {
	bool signaled = WIFSIGNALED(child_status);
	bool stopped = WIFSTOPPED(child_status);
	int child_errno;
	ssize_t nread;

	// Need to close write end *before* reading, otherwise the read will hang
	if (close(child_pipe[1]) == -1)
		errf_exit("failed to close write end of pipe: %s\n", strerror(errno));

	while ((nread = read(child_pipe[0], &child_errno, sizeof(child_errno))) == -1) {
		if (errno != EAGAIN && errno != EINTR)
			break;
	}

	// We can tolerate an error here in case of a single run, but not in general
	// since we could easily exceed the max open file descriptors limit
	if (close(child_pipe[0]) == -1 && (count > 1 || wup_count > 0))
		errf_exit("failed to close read end of pipe: %s\n", strerror(errno));

	if (nread == sizeof(child_errno))
		errf_exit("failed to execute child process: %s\n", strerror(child_errno));
	if (nread == -1)
		errf_exit("failed to read from pipe: %s\n", strerror(errno));
	if (nread > 0)
		err_exit("short read from pipe\n");

	if (WIFEXITED(child_status))
		return;

	if (signaled || stopped) {
		if (child_warnings < MAX_CHILD_WARNINGS) {
			const char *sigdesc;
			int signo;

			signo = signaled ? WTERMSIG(child_status) : WSTOPSIG(child_status);
			sigdesc = strsignal(signo);

			if (!sigdesc)
				sigdesc = "unknown signal";

			if (signaled) {
				errf("child terminated by signal %d (%s)\n", signo, sigdesc);
			} else {
				errf("child stopped by signal %d (%s), %s\n", signo, sigdesc,
					keep_alive ? "kept alive" : "forcibly killing it");
			}

			if (++child_warnings >= MAX_CHILD_WARNINGS)
				err("suppressing any further warnings\n");
		}

		if (stopped && !keep_alive && kill(child_pid, SIGKILL) == -1)
			errf_exit("failed to kill stopped child process (PID=%d)\n", child_pid);
	} else {
		// We should never get here as we don't specify WCONTINUED in wait4
		errf_exit("bad child process status after waiting: 0x%x (bug?)\n", child_status);
	}
}

/**
 * Get precise wall-clock time from clock_gettime.
 */
static inline void wall_time(struct timespec *out) {
	if (clock_gettime(CLOCK_MONOTONIC, out) == -1)
		errf_exit("clock_gettime failed: %s\n", strerror(errno));
}

int main(int argc, char *argv[]) {
	unsigned mute_child_level = 0;
	bool keep_alive_if_stopped = false;
	int opt, child_status, child_pipe[2];
	char **child_argv;

	name = argv[0] ? argv[0] : "bench";

	while ((opt = getopt(argc, argv, "hkn:qQvw:")) != -1) {
		switch (opt) {
			case 'n':
				count = validate_count(optarg);
				break;

			case 'w':
				wup_count = validate_count(optarg);
				break;

			case 'q':
				if (mute_child_level < 1)
					mute_child_level = 1;
				break;

			case 'Q':
				mute_child_level = 2;
				break;

			case 'k':
				keep_alive_if_stopped = true;
				break;

			case 'v':
				version_exit();
				break;

			case 'h':
				help_exit();
				break;

			default:
				usage_exit(NULL);
				break;
		}
	}

	if (optind >= argc)
		usage_exit("need to specify a program to benchmark\n");

	child_argv = argv + optind;

	// If count permits, we can also keep track of all measurements to later
	// calculate the median
	if (count > 1 && count <= MAX_MEASUREMENTS) {
		wall_stats.hist = malloc(sizeof(*wall_stats.hist) * count * 4);

		if (wall_stats.hist) {
			cpu_stats.hist      = wall_stats.hist     + count;
			cpu_user_stats.hist = cpu_stats.hist      + count;
			cpu_sys_stats.hist  = cpu_user_stats.hist + count;
		} else {
			errf("failed allocating history buffers: %s\n", strerror(errno));
			err("skipping median calculation\n");
		}
	}

	for (unsigned long i = 0; i < wup_count; i++) {
		fflush(stderr);
		mute_child(mute_child_level);
		create_pipe(child_pipe);
		child_status = run_child(child_argv, child_pipe[1], NULL);
		check_child_exit(child_status, child_pipe, keep_alive_if_stopped);
	}

	for (unsigned long i = 0; i < count; i++) {
		struct rusage child_rusage;
		struct timespec wstart, wend;
		double wall, cpu_user, cpu_sys;

		fflush(stderr);
		mute_child(mute_child_level);
		create_pipe(child_pipe);

		wall_time(&wstart);
		child_status = run_child(child_argv, child_pipe[1], &child_rusage);
		wall_time(&wend);

		wall     = wend.tv_sec * 1e9 + wend.tv_nsec - wstart.tv_sec * 1e9 - wstart.tv_nsec;
		cpu_user = child_rusage.ru_utime.tv_sec * 1e9 + child_rusage.ru_utime.tv_usec * 1e3;
		cpu_sys  = child_rusage.ru_stime.tv_sec * 1e9 + child_rusage.ru_stime.tv_usec * 1e3;

		update_stats(i, wall, cpu_user, cpu_sys);
		check_child_exit(child_status, child_pipe, keep_alive_if_stopped);
	}

	restore_stderr();
	timing_report();

	return WIFEXITED(child_status) ? WEXITSTATUS(child_status) : EXIT_SUCCESS;
}

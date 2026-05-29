#include "atch.h"
#include <grp.h>

/* Env-var name string, computed from progname at startup. */
const char *session_envvar;

/* Build "NAME_SESSION" from the basename of progname.
** Non-alphanumeric characters are replaced with '_'.
** Uses static storage — called once before any fork. */
static void init_envvar_names(void)
{
	static char envname[128];
	const char *base = strrchr(progname, '/');
	const char *p;
	char *d;
	size_t max;

	base = base ? base + 1 : progname;

	d = envname;
	max = sizeof(envname) - sizeof("_SESSION");
	for (p = base; *p && (size_t)(d - envname) < max; p++)
		*d++ = (*p >= 'a' && *p <= 'z') ? (char)(*p - 'a' + 'A') :
		    ((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) ?
		    *p : '_';
	strcpy(d, "_SESSION");
	session_envvar = envname;
}

/* Returns the basename of the current session socket path. */
const char *session_shortname(void)
{
	const char *p = strrchr(sockname, '/');
	return p ? p + 1 : sockname;
}

/*
** Path of the share guest listener for a session owned by `uid`. Lives in
** world-traversable /tmp (a non-root user cannot create /run/atch); the file is
** left mode 0666 and SO_PEERCRED in the master is the real authorization.
*/
void guest_socket_path(char *buf, size_t size, unsigned uid, const char *name)
{
	const char *base = strrchr(progname, '/');

	base = base ? base + 1 : progname;
	snprintf(buf, size, "/tmp/.%s-guest.%u.%s", base, uid, name);
}

/* Returns the directory where session sockets are stored. */
void get_session_dir(char *buf, size_t size)
{
	const char *home = getenv("HOME");
	const char *base = strrchr(progname, '/');
	struct passwd *pw;

	base = base ? base + 1 : progname;

	/* If $HOME is unset or empty, try the passwd database. */
	if (!home || !*home) {
		pw = getpwuid(getuid());
		if (pw && pw->pw_dir && *pw->pw_dir)
			home = pw->pw_dir;
	}

	/* Use $HOME only if it is set and not the root directory. */
	if (home && *home && strcmp(home, "/") != 0)
		snprintf(buf, size, "%s/.cache/%s", home, base);
	else
		snprintf(buf, size, "/tmp/.%s-%d", base, (int)getuid());
}

/* ───────── Remote session registry (spec item 4) ──────────────────────────
** Maps a bare session name to a remote host so `atch <name>` can reattach
** without re-specifying the host. Flat-line file at ~/.config/<prog>/registry:
**
**   <name> <host> <hostkey-fp-or-"-"> <identity-key-path-or-"-">
**
** Whitespace-separated, one entry per line; a leading '#' is a comment. The
** registry holds NO secrets: first contact uses the user's own ssh (agent /
** config), and a dedicated key thereafter; the fingerprint column is for
** host-key pinning (item 6), the key column names the identity to present.
*/
#define REG_MAXLINE 1024

struct regentry {
	char name[128];
	char host[256];
	char fp[256];		/* pinned host-key fingerprint, or "-" */
	char key[512];		/* identity (private key) path, or "-" */
};

/* Directory for atch config (registry, dedicated key): ~/.config/<prog>. */
void get_config_dir(char *buf, size_t size)
{
	const char *home = getenv("HOME");
	const char *base = strrchr(progname, '/');
	struct passwd *pw;

	base = base ? base + 1 : progname;
	if (!home || !*home) {
		pw = getpwuid(getuid());
		if (pw && pw->pw_dir && *pw->pw_dir)
			home = pw->pw_dir;
	}
	if (home && *home && strcmp(home, "/") != 0)
		snprintf(buf, size, "%s/.config/%s", home, base);
	else
		snprintf(buf, size, "/tmp/.%s-cfg-%d", base, (int)getuid());
}

static void registry_path(char *buf, size_t size)
{
	char dir[512];

	get_config_dir(dir, sizeof(dir));
	snprintf(buf, size, "%s/registry", dir);
}

/* Create the config dir (and its parent) at 0700. Returns 0 on success. */
static int ensure_config_dir(void)
{
	char dir[512], *slash;

	get_config_dir(dir, sizeof(dir));
	slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		mkdir(dir, 0700);
		*slash = '/';
	}
	return (mkdir(dir, 0700) < 0 && errno != EEXIST) ? -1 : 0;
}

/* Find a registry entry by name. Returns 1 and fills *e if found, else 0. */
static int registry_lookup(const char *name, struct regentry *e)
{
	char path[600], line[REG_MAXLINE];
	FILE *f;
	int found = 0;

	registry_path(path, sizeof(path));
	f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		char n[128], h[256], fp[256], k[512];
		int got;

		if (line[0] == '#')
			continue;
		got = sscanf(line, "%127s %255s %255s %511s", n, h, fp, k);
		if (got < 2 || strcmp(n, name) != 0)
			continue;
		memset(e, 0, sizeof(*e));
		snprintf(e->name, sizeof(e->name), "%s", n);
		snprintf(e->host, sizeof(e->host), "%s", h);
		snprintf(e->fp, sizeof(e->fp), "%s", got >= 3 ? fp : "-");
		snprintf(e->key, sizeof(e->key), "%s", got >= 4 ? k : "-");
		found = 1;
		break;
	}
	fclose(f);
	return found;
}

/* Add or replace the entry for `name` (atomic rewrite via temp + rename).
** Pass "-" or NULL for an unknown fingerprint/key. Returns 0 on success. */
static int registry_put(const char *name, const char *host,
			const char *fp, const char *key)
{
	char path[600], tmp[620], line[REG_MAXLINE];
	FILE *in, *out;

	if (ensure_config_dir() < 0)
		return -1;
	registry_path(path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	out = fopen(tmp, "w");
	if (!out)
		return -1;
	fchmod(fileno(out), 0600);

	in = fopen(path, "r");
	if (in) {
		while (fgets(line, sizeof(line), in)) {
			char n[128];

			if (line[0] != '#' && sscanf(line, "%127s", n) == 1 &&
			    strcmp(n, name) == 0)
				continue;	/* drop the stale entry */
			fputs(line, out);
		}
		fclose(in);
	}
	fprintf(out, "%s %s %s %s\n", name, host, fp && *fp ? fp : "-",
		key && *key ? key : "-");
	if (fclose(out) != 0 || rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* Remove the entry for `name`. Returns 1 if removed, 0 if absent, -1 on error. */
static int registry_remove(const char *name)
{
	char path[600], tmp[620], line[REG_MAXLINE];
	FILE *in, *out;
	int removed = 0;

	registry_path(path, sizeof(path));
	in = fopen(path, "r");
	if (!in)
		return 0;
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	out = fopen(tmp, "w");
	if (!out) {
		fclose(in);
		return -1;
	}
	fchmod(fileno(out), 0600);
	while (fgets(line, sizeof(line), in)) {
		char n[128];

		if (line[0] != '#' && sscanf(line, "%127s", n) == 1 &&
		    strcmp(n, name) == 0) {
			removed = 1;
			continue;
		}
		fputs(line, out);
	}
	fclose(in);
	if (fclose(out) != 0 || rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return removed;
}

/*
** Long-path helper for Unix socket operations: saves cwd, chdirs into the
** directory part of path, calls fn(basename), then restores cwd.
** Used by connect_socket and create_socket to handle paths > sun_path limit.
*/
int socket_with_chdir(char *path, int (*fn)(char *))
{
	char *slash = strrchr(path, '/');
	int dirfd, s;

	if (!slash) {
		errno = ENAMETOOLONG;
		return -1;
	}
	dirfd = open(".", O_RDONLY);
	if (dirfd < 0)
		return -1;
	*slash = '\0';
	s = chdir(path) >= 0 ? fn(slash + 1) : -1;
	*slash = '/';
	if (s >= 0 && fchdir(dirfd) < 0) {
		close(s);
		s = -1;
	}
	close(dirfd);
	return s;
}

/* argv[0] from the program */
char *progname;
/* The name of the passed in socket. */
char *sockname;
/* The character used for detaching. Defaults to '^\' */
int detach_char = '\\' - 64;
/* 1 if we should not interpret the suspend character. */
int no_suspend;
/* The default redraw method. REDRAW_UNSPEC = auto: winch if tty, none otherwise. */
int redraw_method = REDRAW_UNSPEC;
/* Clear method. CLEAR_UNSPEC = auto: move if tty, none otherwise. */
int clear_method = CLEAR_UNSPEC;
int quiet = 0;
/* 1 if we should not send ansi sequences to the terminal */
int no_ansiterm = 0;

/*
** The original terminal settings. Shared between the master and attach
** processes. The master uses it to initialize the pty, and the attacher uses
** it to restore the original settings.
*/
struct termios orig_term;
int dont_have_tty;

/* Parse a size string: bare number, or number with k/K (×1024) or m/M (×1048576).
** Writes result to *out. Returns 0 on success, 1 on error. */
static int parse_size(const char *s, size_t *out)
{
	char *end;
	unsigned long v;

	if (!s || !*s)
		return 1;
	v = strtoul(s, &end, 10);
	if (end == s)
		return 1;
	if (*end == 'k' || *end == 'K') {
		v *= 1024;
		end++;
	} else if (*end == 'm' || *end == 'M') {
		v *= 1024 * 1024;
		end++;
	}
	if (*end != '\0')
		return 1;
	*out = (size_t)v;
	return 0;
}

/*
** Parse option flags from argv/argc. Stops at '--' or a non-option argument.
** Returns 0 on success, 1 on error (message already printed).
*/
static int parse_options(int *argc, char ***argv)
{
	while (*argc >= 1 && ***argv == '-') {
		char *p;

		if (strcmp((*argv)[0], "--") == 0) {
			++(*argv);
			--(*argc);
			break;
		}

		for (p = (*argv)[0] + 1; *p; ++p) {
			if (*p == 'E')
				detach_char = -1;
			else if (*p == 'z')
				no_suspend = 1;
			else if (*p == 'q')
				quiet = 1;
			else if (*p == 't')
				no_ansiterm = 1;
			else if (*p == 'e') {
				++(*argv);
				--(*argc);
				if (*argc < 1) {
					printf("%s: No escape character "
					       "specified.\n", progname);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				if ((*argv)[0][0] == '^' && (*argv)[0][1]) {
					if ((*argv)[0][1] == '?')
						detach_char = '\177';
					else
						detach_char =
						    (*argv)[0][1] & 037;
				} else
					detach_char = (*argv)[0][0];
				break;
			} else if (*p == 'r') {
				++(*argv);
				--(*argc);
				if (*argc < 1) {
					printf("%s: No redraw method "
					       "specified.\n", progname);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				if (strcmp((*argv)[0], "none") == 0)
					redraw_method = REDRAW_NONE;
				else if (strcmp((*argv)[0], "ctrl_l") == 0)
					redraw_method = REDRAW_CTRL_L;
				else if (strcmp((*argv)[0], "winch") == 0)
					redraw_method = REDRAW_WINCH;
				else {
					printf("%s: Invalid redraw method "
					       "specified.\n", progname);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				break;
			} else if (*p == 'R') {
				++(*argv);
				--(*argc);
				if (*argc < 1) {
					printf("%s: No clear method "
					       "specified.\n", progname);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				if (strcmp((*argv)[0], "none") == 0)
					clear_method = CLEAR_NONE;
				else if (strcmp((*argv)[0], "move") == 0)
					clear_method = CLEAR_MOVE;
				else {
					printf("%s: Invalid clear method "
					       "specified.\n", progname);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				break;
			} else if (*p == 'C') {
				++(*argv);
				--(*argc);
				if (*argc < 1) {
					printf("%s: No log size "
					       "specified.\n", progname);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				if (parse_size((*argv)[0], &log_max_size)) {
					printf("%s: Invalid log size "
					       "'%s'.\n", progname, (*argv)[0]);
					printf("Try '%s --help' for more "
					       "information.\n", progname);
					return 1;
				}
				break;
			} else {
				printf("%s: Invalid option '-%c'\n",
				       progname, *p);
				printf("Try '%s --help' for more "
				       "information.\n", progname);
				return 1;
			}
		}
		++(*argv);
		--(*argc);
	}
	return 0;
}

/* Expand a bare session name to its full socket path in-place. */
static void expand_sockname(void)
{
	char dir[512];
	size_t fulllen;
	char *full;
	char *slash;

	if (strchr(sockname, '/') != NULL)
		return;

	get_session_dir(dir, sizeof(dir));
	slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		mkdir(dir, 0700);
		*slash = '/';
	}
	mkdir(dir, 0700);
	fulllen = strlen(dir) + 1 + strlen(sockname);
	full = malloc(fulllen + 1);
	snprintf(full, fulllen + 1, "%s/%s", dir, sockname);
	sockname = full;
}

/* Return argv unchanged if argc > 0; otherwise return a {shell, NULL} argv. */
static char **use_shell_if_no_cmd(int argc, char **argv)
{
	static char *shell_argv[2];
	const char *shell;
	struct passwd *pw;

	if (argc > 0)
		return argv;
	shell = getenv("SHELL");
	if (!shell || !*shell) {
		pw = getpwuid(getuid());
		if (pw && pw->pw_shell && *pw->pw_shell)
			shell = pw->pw_shell;
	}
	if (!shell || !*shell)
		shell = "/bin/sh";
	shell_argv[0] = (char *)shell;
	shell_argv[1] = NULL;
	return shell_argv;
}

/* Snapshot terminal settings; sets dont_have_tty if not a tty. */
static void save_term(void)
{
	if (tcgetattr(0, &orig_term) < 0) {
		memset(&orig_term, 0, sizeof(struct termios));
		dont_have_tty = 1;
	}
}

/* Print error and return 1 if no tty is available. */
static int require_tty(void)
{
	if (dont_have_tty) {
		printf("%s: attaching to a session requires a terminal.\n",
		       progname);
		return 1;
	}
	return 0;
}

/* Consume first arg as session name, expand it, advance argc/argv. */
static int consume_session(int *argc, char ***argv)
{
	if (*argc < 1) {
		printf("%s: No session was specified.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}
	sockname = **argv;
	++(*argv);
	--(*argc);
	expand_sockname();
	return 0;
}

/* True if arg matches any of the given names (NULL slots are ignored). */
static int is_cmd(const char *arg, const char *a, const char *b, const char *c)
{
	return strcmp(arg, a) == 0 ||
	    (b && strcmp(arg, b) == 0) || (c && strcmp(arg, c) == 0);
}

/* atch list [-a] */
static int cmd_list(int argc, char **argv)
{
	int show_all = 0;

	while (argc >= 1 && strcmp(argv[0], "-a") == 0) {
		show_all = 1;
		argc--;
		argv++;
	}
	return list_main(show_all);
}

/* atch current
** SESSION_ENVVAR holds the colon-separated ancestry chain, outermost first.
** A single (non-nested) session has no colon. */
static int cmd_current(void)
{
	const char *chain = getenv(SESSION_ENVVAR);
	char *copy, *seg, *colon;
	const char *name;
	int first;

	if (!chain || !*chain)
		return 1;

	copy = strdup(chain);
	if (!copy)
		return 1;

	first = 1;
	seg = copy;
	for (;;) {
		colon = strchr(seg, ':');
		if (colon)
			*colon = '\0';
		name = strrchr(seg, '/');
		if (!first)
			printf(" > ");
		printf("%s", name ? name + 1 : seg);
		first = 0;
		if (!colon)
			break;
		seg = colon + 1;
	}
	printf("\n");
	free(copy);
	return 0;
}

/* atch attach <session> — strict attach, fail if missing */
static int cmd_attach(int argc, char **argv)
{
	if (parse_options(&argc, &argv))
		return 1;
	if (consume_session(&argc, &argv))
		return 1;
	if (parse_options(&argc, &argv))
		return 1;
	if (argc > 0) {
		printf("%s: Invalid number of arguments.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}
	save_term();
	if (require_tty())
		return 1;
	return attach_main(0);
}

/* atch new <session> [cmd...] — create session and attach */
static int cmd_new(int argc, char **argv)
{
	if (parse_options(&argc, &argv))
		return 1;
	if (consume_session(&argc, &argv))
		return 1;
	if (parse_options(&argc, &argv))
		return 1;
	argv = use_shell_if_no_cmd(argc, argv);
	save_term();
	if (require_tty())
		return 1;
	if (master_main(argv, 1, 0) != 0)
		return 1;
	if (!quiet)
		printf("%s: session '%s' created\n", progname,
		       session_shortname());
	return attach_main(0);
}

/* atch start <session> [cmd...] — create detached */
static int cmd_start(int argc, char **argv)
{
	if (parse_options(&argc, &argv))
		return 1;
	if (consume_session(&argc, &argv))
		return 1;
	if (parse_options(&argc, &argv))
		return 1;
	argv = use_shell_if_no_cmd(argc, argv);
	save_term();
	if (master_main(argv, 0, 0) != 0)
		return 1;
	if (!quiet)
		printf("%s: session '%s' started\n", progname,
		       session_shortname());
	return 0;
}

/* atch run <session> [cmd...] — create, master stays in foreground */
static int cmd_run(int argc, char **argv)
{
	if (parse_options(&argc, &argv))
		return 1;
	if (consume_session(&argc, &argv))
		return 1;
	if (parse_options(&argc, &argv))
		return 1;
	argv = use_shell_if_no_cmd(argc, argv);
	save_term();
	return master_main(argv, 0, 1);
}

/* atch push <session> — pipe stdin into session */
static int cmd_push(int argc, char **argv)
{
	if (consume_session(&argc, &argv))
		return 1;
	if (argc > 0) {
		printf("%s: Invalid number of arguments.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}
	return push_main();
}

/* atch kill <session> — stop session */
static int cmd_kill(int argc, char **argv)
{
	int force = 0;

	/* Accept -f / --force before or after the session name. */
	while (argc >= 1 && (strcmp(argv[0], "-f") == 0 ||
			     strcmp(argv[0], "--force") == 0)) {
		force = 1;
		argc--;
		argv++;
	}
	if (consume_session(&argc, &argv))
		return 1;
	while (argc >= 1 && (strcmp(argv[0], "-f") == 0 ||
			     strcmp(argv[0], "--force") == 0)) {
		force = 1;
		argc--;
		argv++;
	}
	if (argc > 0) {
		printf("%s: Invalid number of arguments.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}
	return kill_main(force);
}

/* atch clear <session> — truncate the on-disk session log */
static int cmd_clear(int argc, char **argv)
{
	char log_path[600];
	int fd;

	if (argc > 0) {
		if (consume_session(&argc, &argv))
			return 1;
	} else {
		const char *chain = getenv(SESSION_ENVVAR);
		const char *last;

		if (!chain || !*chain) {
			printf("%s: No session was specified.\n", progname);
			printf("Try '%s --help' for more information.\n",
			       progname);
			return 1;
		}
		last = strrchr(chain, ':');
		sockname = (char *)(last ? last + 1 : chain);
	}
	if (argc > 0) {
		printf("%s: Invalid number of arguments.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}
	snprintf(log_path, sizeof(log_path), "%s.log", sockname);
	fd = open(log_path, O_WRONLY | O_TRUNC);
	if (fd >= 0) {
		close(fd);
		if (!quiet)
			printf("%s: session '%s' log cleared\n",
			       progname, session_shortname());
	} else if (errno != ENOENT) {
		printf("%s: %s: %s\n", progname, log_path, strerror(errno));
		return 1;
	}
	return 0;
}

/* Scan log fd backward and return the byte offset to seek to before
** printing the last nlines lines of output. */
static off_t find_tail_start(int fd, off_t size, int nlines)
{
	char buf[BUFSIZE];
	int count = 0;
	off_t pos = size;

	while (pos > 0 && count <= nlines) {
		off_t chunk = pos > (off_t)sizeof(buf) ? (off_t)sizeof(buf) : pos;
		ssize_t n;
		ssize_t i;

		pos -= chunk;
		lseek(fd, pos, SEEK_SET);
		n = read(fd, buf, (size_t)chunk);
		if (n <= 0)
			break;
		for (i = n - 1; i >= 0; i--) {
			if (buf[i] == '\n') {
				if (++count > nlines)
					return pos + i + 1;
			}
		}
	}
	return 0;
}

/* atch tail [-f] [-n N] <session> — print last N lines of session log */
static int cmd_tail(int argc, char **argv)
{
	int follow = 0, nlines = 10;
	char log_path[600];
	unsigned char rbuf[BUFSIZE];
	off_t size, start;
	ssize_t n;
	int fd;

	/* Parse -f and -n N (also -nN) before the session name */
	while (argc >= 1 && argv[0][0] == '-' && argv[0][1] != '\0') {
		if (strcmp(argv[0], "-f") == 0) {
			follow = 1;
			argc--;
			argv++;
		} else if (strcmp(argv[0], "-n") == 0) {
			if (argc < 2) {
				printf("%s: -n requires an argument\n", progname);
				printf("Try '%s --help' for more information.\n",
				       progname);
				return 1;
			}
			nlines = atoi(argv[1]);
			argc -= 2;
			argv += 2;
		} else if (strncmp(argv[0], "-n", 2) == 0 &&
			   argv[0][2] != '\0') {
			nlines = atoi(argv[0] + 2);
			argc--;
			argv++;
		} else {
			printf("%s: Invalid option '%s'\n", progname, argv[0]);
			printf("Try '%s --help' for more information.\n",
			       progname);
			return 1;
		}
	}
	if (nlines < 1)
		nlines = 1;

	if (consume_session(&argc, &argv))
		return 1;
	if (argc > 0) {
		printf("%s: Invalid number of arguments.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}

	snprintf(log_path, sizeof(log_path), "%s.log", sockname);
	fd = open(log_path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			printf("%s: no log for session '%s'\n", progname,
			       session_shortname());
		else
			printf("%s: %s: %s\n", progname, log_path,
			       strerror(errno));
		return 1;
	}

	size = lseek(fd, 0, SEEK_END);
	if (size > 0) {
		start = find_tail_start(fd, size, nlines);
		lseek(fd, start, SEEK_SET);
		while ((n = read(fd, rbuf, sizeof(rbuf))) > 0)
			write(1, rbuf, (size_t)n);
	}

	if (follow) {
		signal(SIGPIPE, SIG_IGN);
		for (;;) {
			usleep(250000);
			while ((n = read(fd, rbuf, sizeof(rbuf))) > 0)
				write(1, rbuf, (size_t)n);
		}
	}

	close(fd);
	return 0;
}

static int cmd_rm(int argc, char **argv)
{
	int all = 0;

	if (argc >= 1 && strcmp(argv[0], "-a") == 0) {
		all = 1;
		argc--;
		argv++;
	}

	if (all) {
		if (argc > 0) {
			printf("%s: Invalid number of arguments.\n", progname);
			printf("Try '%s --help' for more information.\n",
			       progname);
			return 1;
		}
		return rm_main(1);
	}

	if (consume_session(&argc, &argv))
		return 1;
	if (argc > 0) {
		printf("%s: Invalid number of arguments.\n", progname);
		printf("Try '%s --help' for more information.\n", progname);
		return 1;
	}
	return rm_main(0);
}

/* Default: atch <session> [cmd...] — attach-or-create */
static int cmd_open(char *session, int argc, char **argv)
{
	sockname = session;
	expand_sockname();
	if (parse_options(&argc, &argv))
		return 1;
	argv = use_shell_if_no_cmd(argc, argv);
	save_term();
	if (require_tty())
		return 1;
	if (attach_main(1) != 0) {
		if (errno == ECONNREFUSED || errno == ENOENT) {
			int saved_errno = errno;

			replay_session_log(saved_errno);
			if (saved_errno == ECONNREFUSED)
				unlink(sockname);
			if (master_main(argv, 1, 0) != 0)
				return 1;
			if (!quiet)
				printf("%s: session '%s' created\n", progname,
				       session_shortname());
		}
		return attach_main(0);
	}
	return 0;
}

/*
** atch remote add <name> <host>   — record/replace a name -> host mapping
** atch remote ls                  — list registered remote sessions
** atch remote rm <name>           — forget a mapping
** The registry holds no secrets; -H bootstrap (item 5) also writes here.
*/
static int cmd_remote(int argc, char **argv)
{
	char path[600], line[REG_MAXLINE];
	FILE *f;
	int n;

	if (argc < 1) {
		printf("usage: %s remote <add|ls|rm> ...\n", progname);
		return 1;
	}

	if (!strcmp(argv[0], "add")) {
		if (argc != 3) {
			printf("usage: %s remote add <name> <host>\n", progname);
			return 1;
		}
		if (registry_put(argv[1], argv[2], "-", "-") != 0) {
			printf("%s: cannot write registry: %s\n", progname,
			       strerror(errno));
			return 1;
		}
		if (!quiet)
			printf("%s: remote '%s' -> %s\n", progname, argv[1],
			       argv[2]);
		return 0;
	}

	if (!strcmp(argv[0], "ls") || !strcmp(argv[0], "list")) {
		if (argc != 1) {
			printf("usage: %s remote ls\n", progname);
			return 1;
		}
		n = 0;
		registry_path(path, sizeof(path));
		f = fopen(path, "r");
		if (f) {
			while (fgets(line, sizeof(line), f)) {
				char nm[128], h[256], fp[256];
				int got;

				if (line[0] == '#')
					continue;
				got = sscanf(line, "%127s %255s %255s", nm, h,
					     fp);
				if (got < 2)
					continue;
				printf("%-20s %s%s\n", nm, h,
				       (got >= 3 && strcmp(fp, "-"))
				       ? "  [host-key pinned]" : "");
				n++;
			}
			fclose(f);
		}
		if (n == 0 && !quiet)
			printf("%s: no remote sessions registered\n", progname);
		return 0;
	}

	if (!strcmp(argv[0], "rm")) {
		int r;

		if (argc != 2) {
			printf("usage: %s remote rm <name>\n", progname);
			return 1;
		}
		r = registry_remove(argv[1]);
		if (r < 0) {
			printf("%s: cannot write registry: %s\n", progname,
			       strerror(errno));
			return 1;
		}
		if (r == 0) {
			printf("%s: no such remote '%s'\n", progname, argv[1]);
			return 1;
		}
		if (!quiet)
			printf("%s: remote '%s' removed\n", progname, argv[1]);
		return 0;
	}

	printf("%s: remote: unknown subcommand '%s'\n", progname, argv[0]);
	return 1;
}

/*
** atch share <session> --to <spec> [-m MINUTES] [--write]
** Resolve the target users/groups to numeric ids, write a <session>.share
** descriptor next to the socket, and tell the running master to arm the guest
** listener. Read-only by default; --write (or per-target :rw) grants input.
*/
static int cmd_share(int argc, char **argv)
{
	char *spec = NULL, *name = NULL;
	long minutes = 60;
	int write_default = 0, i, ntargets = 0;
	char sharepath[600], gp[256], *buf, *save, *tok;
	struct stat st;
	time_t expiry;
	FILE *f;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--to") == 0 && i + 1 < argc)
			spec = argv[++i];
		else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
			minutes = atol(argv[++i]);
		else if (!strcmp(argv[i], "--write") || !strcmp(argv[i], "-w"))
			write_default = 1;
		else if (argv[i][0] != '-' && !name)
			name = argv[i];
		else {
			printf("%s: share: unexpected argument '%s'\n", progname,
			       argv[i]);
			return 1;
		}
	}
	if (!name || !spec) {
		printf("usage: %s share <session> --to "
		       "<user|@group[:rw|:ro]>[,...] [-m MINUTES] [--write]\n",
		       progname);
		return 1;
	}

	sockname = name;
	expand_sockname();
	if (stat(sockname, &st) < 0 || !S_ISSOCK(st.st_mode)) {
		printf("%s: session '%s' does not exist\n", progname,
		       session_shortname());
		return 1;
	}

	expiry = minutes > 0 ? time(NULL) + minutes * 60 : 0;

	snprintf(sharepath, sizeof(sharepath), "%s.share", sockname);
	f = fopen(sharepath, "w");
	if (!f) {
		printf("%s: %s: %s\n", progname, sharepath, strerror(errno));
		return 1;
	}
	fchmod(fileno(f), 0600);
	fprintf(f, "expiry %ld\n", (long)expiry);

	buf = strdup(spec);
	if (!buf) {
		fclose(f);
		unlink(sharepath);
		return 1;
	}
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		int w = write_default;
		char *colon = strrchr(tok, ':');

		if (colon) {
			if (!strcmp(colon + 1, "rw"))
				w = 1;
			else if (!strcmp(colon + 1, "ro"))
				w = 0;
			else {
				printf("%s: share: bad mode in '%s'\n", progname,
				       tok);
				goto fail;
			}
			*colon = '\0';
		}
		if (tok[0] == '@') {
			struct group *gr = getgrnam(tok + 1);

			if (!gr) {
				printf("%s: share: unknown group '%s'\n",
				       progname, tok + 1);
				goto fail;
			}
			fprintf(f, "gid %u %d\n", (unsigned)gr->gr_gid, w);
		} else {
			struct passwd *pw = getpwnam(tok);

			if (!pw) {
				printf("%s: share: unknown user '%s'\n",
				       progname, tok);
				goto fail;
			}
			fprintf(f, "uid %u %d\n", (unsigned)pw->pw_uid, w);
		}
		ntargets++;
	}
	free(buf);
	fclose(f);

	if (ntargets == 0) {
		printf("%s: share: no valid targets in --to\n", progname);
		unlink(sharepath);
		return 1;
	}

	if (notify_master(MSG_SHARE) != 0) {
		unlink(sharepath);
		return 1;
	}

	if (!quiet) {
		guest_socket_path(gp, sizeof(gp), (unsigned)getuid(),
				  session_shortname());
		printf("%s: session '%s' shared to %d target(s)", progname,
		       session_shortname(), ntargets);
		if (expiry) {
			char age[32];

			format_age(minutes * 60, age, sizeof(age));
			printf(", expires in %s", age);
		}
		printf("\n  guest socket: %s\n  others can run: %s join %s\n",
		       gp, progname, session_shortname());
	}
	return 0;

 fail:
	free(buf);
	fclose(f);
	unlink(sharepath);
	return 1;
}

/* atch unshare <session> — revoke a share early. */
static int cmd_unshare(int argc, char **argv)
{
	char sharepath[600];

	if (argc < 1) {
		printf("usage: %s unshare <session>\n", progname);
		return 1;
	}
	sockname = argv[0];
	expand_sockname();
	snprintf(sharepath, sizeof(sharepath), "%s.share", sockname);
	unlink(sharepath);
	if (notify_master(MSG_UNSHARE) != 0)
		return 1;
	if (!quiet)
		printf("%s: session '%s' unshared\n", progname,
		       session_shortname());
	return 0;
}

/*
** atch join <session> — attach to a session another user has shared. Discovers
** the guest socket by scanning /tmp; the master enforces SO_PEERCRED auth.
*/
static int cmd_join(int argc, char **argv)
{
	const char *base = strrchr(progname, '/');
	char prefix[128], found[320];
	int nfound = 0;
	DIR *d;
	struct dirent *de;

	base = base ? base + 1 : progname;
	if (argc < 1) {
		printf("usage: %s join <session>\n", progname);
		return 1;
	}

	snprintf(prefix, sizeof(prefix), ".%s-guest.", base);
	d = opendir("/tmp");
	if (!d) {
		printf("%s: /tmp: %s\n", progname, strerror(errno));
		return 1;
	}
	while ((de = readdir(d)) != NULL) {
		size_t plen = strlen(prefix);
		const char *dot;

		if (strncmp(de->d_name, prefix, plen) != 0)
			continue;
		/* remainder is <uid>.<name>; match the trailing name */
		dot = strchr(de->d_name + plen, '.');
		if (!dot || strcmp(dot + 1, argv[0]) != 0)
			continue;
		if (nfound == 0)
			snprintf(found, sizeof(found), "/tmp/%s", de->d_name);
		nfound++;
	}
	closedir(d);

	if (nfound == 0) {
		printf("%s: no shared session '%s' found\n", progname, argv[0]);
		return 1;
	}
	if (nfound > 1) {
		printf("%s: multiple shared sessions named '%s' (different "
		       "owners); cannot disambiguate\n", progname, argv[0]);
		return 1;
	}

	sockname = strdup(found);
	save_term();
	if (require_tty())
		return 1;
	return attach_main(0);
}

static void usage(void)
{
	printf(PACKAGE_NAME " - version %s, compiled on %s at %s.\n"
	       "Usage:\n"
	       "  " PACKAGE_NAME " [<session> [command...]]"
	       "\t\tAttach to session or create it\n"
	       "  " PACKAGE_NAME " <command> [options] ...\n"
	       "\n"
	       "Commands:\n"
	       "  attach  <session>"
	       "\t\t\tStrict attach (fail if session missing)\n"
	       "  new     <session> [command...]"
	       "\tCreate session and attach\n"
	       "  start   <session> [command...]"
	       "\tCreate session, detached\n"
	       "  run     <session> [command...]"
	       "\tCreate session, master in foreground\n"
	       "  push    <session>"
	       "\t\t\tPipe stdin into session\n"
	       "  kill    [-f] <session>"
	       "\t\tStop session (SIGTERM then SIGKILL)\n"
	       "    -f, --force\t\t\tSkip grace period, send SIGKILL immediately\n"
	       "  clear   [<session>]"
	       "\t\t\tTruncate the session log\n"
	       "  tail    [-f] [-n N] <session>"
	       "\tPrint last N lines of session log\n"
	       "    -f\t\t\t\tFollow log output\n"
	       "    -n <lines>\t\t\tNumber of lines (default 10)\n"
	       "  list    [-a]\t\t\t\tList sessions (-a includes exited)\n"
	       "  rm      [-a] [<session>]"
	       "\t\tRemove stale/exited session(s)\n"
	       "    -a\t\t\t\tRemove all stale and exited sessions\n"
	       "  share   <session> --to <spec> [-m MIN] [--write]\n"
	       "\t\t\t\tShare a session (read-only by default)\n"
	       "    --to <user|@group[:rw|:ro]>[,...]\tGrant targets\n"
	       "    -m <minutes>\t\tAuto-revoke after MIN (0 = never; default 60)\n"
	       "    --write\t\t\tGrant input to all targets by default\n"
	       "  join    <session>\t\t\tAttach to a session shared with you\n"
	       "  unshare <session>\t\t\tRevoke a share early\n"
	       "  remote  <add|ls|rm> ...\t\tManage remote session registry\n"
	       "    add <name> <host>\t\tMap a session name to a remote host\n"
	       "    ls\t\t\t\tList registered remote sessions\n"
	       "    rm <name>\t\t\tForget a mapping\n"
	       "  current\t\t\t\tPrint current session name\n"
	       "\n"
	       "Options:\n"
	       "  -e <char>\tSet detach character (default: ^\\)\n"
	       "  -E\t\tDisable detach character\n"
	       "  -r <method>\tRedraw method: none | ctrl_l | winch\n"
	       "  -R <method>\tClear method:  none | move\n"
	       "  -z\t\tDisable suspend key\n"
	       "  -q\t\tSuppress messages\n"
	       "  -t\t\tDisable VT100 assumptions\n"
	       "  -C <size>\tLog cap: 0=disable, e.g. 128k, 4m (default 1m)\n"
	       "\nURL: " PACKAGE_URL "\n\n",
	       PACKAGE_VERSION, __DATE__, __TIME__);
	exit(0);
}

int main(int argc, char **argv)
{
	const char *cmd;

	progname = argv[0];
	init_envvar_names();
	++argv;
	--argc;

	if (argc < 1)
		usage();

	/* --help / --version / -h */
	if (strcmp(*argv, "--help") == 0 || strcmp(*argv, "-h") == 0 ||
	    strcmp(*argv, "?") == 0)
		usage();
	if (strcmp(*argv, "--version") == 0) {
		printf(PACKAGE_NAME " - version %s, compiled on %s at %s.\n",
		       PACKAGE_VERSION, __DATE__, __TIME__);
		return 0;
	}

	/*
	 ** Pre-pass: consume any global options (-q, -e, -E, -r, -R, -z, -t)
	 ** that appear before the subcommand or legacy mode letter.  We stop
	 ** (without error) as soon as we see a flag that is not a known global
	 ** option, so legacy mode letters like -a/-n still reach the dispatcher
	 ** below unchanged.
	 */
	while (argc >= 1 && argv[0][0] == '-' && argv[0][1] != '\0' &&
	       argv[0][1] != '-') {
		char c = argv[0][1];

		if (c != 'e' && c != 'E' && c != 'r' && c != 'R' &&
		    c != 'z' && c != 'q' && c != 't' && c != 'C')
			break;
		if (parse_options(&argc, &argv))
			return 1;
	}
	if (argc < 1)
		usage();

	/*
	 ** Legacy backward-compat: flag-based syntax (-a, -c, -n, -N, etc.).
	 ** Detected when the first argument is a single-dash flag.
	 */
	if (argc >= 1 && argv[0][0] == '-' && argv[0][1] != '\0' &&
	    argv[0][1] != '-') {
		int mode = (*argv)[1];

		++argv;
		--argc;
		if (mode == '?' || mode == 'h')
			usage();
		if (mode == 'l')
			return cmd_list(argc, argv);
		if (mode == 'i')
			return cmd_current();
		if (mode != 'a' && mode != 'A' && mode != 'c' &&
		    mode != 'n' && mode != 'N' && mode != 'p' && mode != 'k') {
			printf("%s: Invalid mode '-%c'\n", progname, mode);
			printf("Try '%s --help' for more information.\n",
			       progname);
			return 1;
		}

		if (argc < 1) {
			printf("%s: No session was specified.\n", progname);
			printf("Try '%s --help' for more information.\n",
			       progname);
			return 1;
		}
		sockname = *argv;
		++argv;
		--argc;
		expand_sockname();

		if (mode == 'p') {
			if (argc > 0) {
				printf("%s: Invalid number of arguments.\n",
				       progname);
				printf("Try '%s --help' for more "
				       "information.\n", progname);
				return 1;
			}
			return push_main();
		}
		if (mode == 'k') {
			if (argc > 0) {
				printf("%s: Invalid number of arguments.\n",
				       progname);
				printf("Try '%s --help' for more "
				       "information.\n", progname);
				return 1;
			}
			return kill_main(0);
		}

		if (parse_options(&argc, &argv))
			return 1;
		if (mode != 'a')
			argv = use_shell_if_no_cmd(argc, argv);
		save_term();
		if (dont_have_tty && mode != 'n' && mode != 'N') {
			printf("%s: attaching to a session requires a "
			       "terminal.\n", progname);
			return 1;
		}

		if (mode == 'a') {
			if (argc > 0) {
				printf("%s: Invalid number of arguments.\n",
				       progname);
				printf("Try '%s --help' for more "
				       "information.\n", progname);
				return 1;
			}
			return attach_main(0);
		}
		if (mode == 'n')
			return master_main(argv, 0, 0);
		if (mode == 'N')
			return master_main(argv, 0, 1);
		if (mode == 'c') {
			if (master_main(argv, 1, 0) != 0)
				return 1;
			return attach_main(0);
		}
		/* mode == 'A' */
		if (attach_main(1) != 0) {
			if (errno == ECONNREFUSED || errno == ENOENT) {
				int saved_errno = errno;

				replay_session_log(saved_errno);
				if (saved_errno == ECONNREFUSED)
					unlink(sockname);
				if (master_main(argv, 1, 0) != 0)
					return 1;
			}
			return attach_main(0);
		}
		return 0;
	}

	/* New command-based dispatch */
	cmd = *argv;
	++argv;
	--argc;

	if (is_cmd(cmd, "list", "l", "ls"))
		return cmd_list(argc, argv);
	if (is_cmd(cmd, "current", NULL, NULL))
		return cmd_current();
	if (is_cmd(cmd, "attach", "a", NULL))
		return cmd_attach(argc, argv);
	if (is_cmd(cmd, "new", "n", NULL))
		return cmd_new(argc, argv);
	if (is_cmd(cmd, "start", "s", NULL))
		return cmd_start(argc, argv);
	if (is_cmd(cmd, "run", NULL, NULL))
		return cmd_run(argc, argv);
	if (is_cmd(cmd, "push", "p", NULL))
		return cmd_push(argc, argv);
	if (is_cmd(cmd, "kill", "k", NULL))
		return cmd_kill(argc, argv);
	if (is_cmd(cmd, "clear", NULL, NULL))
		return cmd_clear(argc, argv);
	if (is_cmd(cmd, "tail", NULL, NULL))
		return cmd_tail(argc, argv);
	if (is_cmd(cmd, "rm", NULL, NULL))
		return cmd_rm(argc, argv);
	if (is_cmd(cmd, "share", NULL, NULL))
		return cmd_share(argc, argv);
	if (is_cmd(cmd, "join", "j", NULL))
		return cmd_join(argc, argv);
	if (is_cmd(cmd, "unshare", NULL, NULL))
		return cmd_unshare(argc, argv);
	if (is_cmd(cmd, "remote", NULL, NULL))
		return cmd_remote(argc, argv);

	/* Smart default: treat first arg as session name → attach-or-create */
	return cmd_open((char *)cmd, argc, argv);
}

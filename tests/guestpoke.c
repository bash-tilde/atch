/*
** guestpoke <guest-socket> [push-string] — test helper for the cross-user
** sharing tests. Connects to a session's guest listener (which makes the master
** read SO_PEERCRED and authorize/audit the peer) and, if a push string is
** given, sends it as MSG_PUSH packets. Run under su(1) as the user whose
** access is being tested; the kernel vouches for that uid to the master.
**
** Deliberately tiny and dependency-free so it compiles with the same musl gcc
** as atch inside the build container. The packet layout mirrors struct packet
** in atch.h (type, len, 8-byte union) — 10 bytes on the wire.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

struct wire_packet {
	unsigned char type;	/* 0 = MSG_PUSH */
	unsigned char len;
	unsigned char buf[8];
};

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int s;

	if (argc < 2) {
		fprintf(stderr, "usage: guestpoke <socket> [push-string]\n");
		return 2;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return 2;
	}
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 3;
	}

	/* Let the master accept + authorize this connection first. */
	usleep(300000);

	/* `--pkt TYPE LEN`: send one raw control packet (e.g. MSG_REDRAW=4 with
	 ** len=REDRAW_WINCH=3) to test that read-only guests are gated. */
	if (argc >= 5 && strcmp(argv[2], "--pkt") == 0) {
		struct wire_packet p;

		memset(&p, 0, sizeof(p));
		p.type = (unsigned char)atoi(argv[3]);
		p.len = (unsigned char)atoi(argv[4]);
		if (write(s, &p, sizeof(p)) != (ssize_t) sizeof(p)) {
			perror("write");
			return 4;
		}
	} else if (argc >= 3) {
		const char *msg = argv[2];
		size_t off = 0, total = strlen(msg);

		while (off < total) {
			struct wire_packet p;
			size_t chunk = total - off;

			if (chunk > sizeof(p.buf))
				chunk = sizeof(p.buf);
			memset(&p, 0, sizeof(p));
			p.type = 0;	/* MSG_PUSH */
			p.len = (unsigned char)chunk;
			memcpy(p.buf, msg + off, chunk);
			if (write(s, &p, sizeof(p)) != (ssize_t) sizeof(p)) {
				perror("write");
				return 4;
			}
			off += chunk;
		}
	}

	/* Hold the connection open briefly so the master processes everything
	 ** (audit line, and any pushed bytes through the pty) before we close. */
	usleep(500000);
	return 0;
}

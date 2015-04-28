
#include <stdio.h>
#include <stdlib.h>

#include <netdb.h>
#include <ares.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>

extern ares_channel osmo_ares_channel;


static void ares_cb(void *arg, int status, int timeouts, struct hostent *hostent)
{
	struct in_addr *ia;
	int i;

	printf("Callback called: status=%d, timeouts=%d\n", status, timeouts);

	if (status != ARES_SUCCESS)
		return;

	if (hostent->h_length != sizeof(struct in_addr))
		return;

	for (i = 0, ia = (struct in_addr *) hostent->h_addr_list[i]; ia;
	     i++, ia = (struct in_addr *) hostent->h_addr_list[i]) {
		printf("%s -> %s\n", hostent->h_name, inet_ntoa(*ia));
	}

	exit(0);
}

int main(int argc, char **argv)
{
	osmo_ares_init();

	ares_gethostbyname(osmo_ares_channel, "localhost", AF_INET,
			   ares_cb, NULL);

	while (1) {
		osmo_select_main(0);
	}

	exit(1);
}

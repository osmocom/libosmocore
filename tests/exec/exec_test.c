#include <osmocom/core/utils.h>
#include <osmocom/core/exec.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

static void env_dump(char **env)
{
	char **ent;

	for (ent = env; *ent; ent++)
		printf("\t%s\n", *ent);
}

static void test_env_filter(void)
{
	char *out[256];
	char *env_in[] = {
		"FOO=1",
		"BAR=2",
		"USER=mahlzeit",
		"BAZ=3",
		"SHELL=/bin/sh",
		NULL
	};
	const char *filter[] = {
		"SHELL",
		"USER",
		NULL
	};
	int rc;

	printf("\n==== osmo_environment_filter ====\n");

	printf("Input Environment:\n");
	env_dump(env_in);
	printf("Input Whitelist:\n");
	env_dump((char **) filter);
	rc = osmo_environment_filter(out, ARRAY_SIZE(out), env_in, filter);
	printf("Output Environment (%d):\n", rc);
	env_dump(out);
	OSMO_ASSERT(rc == 3);

	printf("Testing for NULL out\n");
	rc = osmo_environment_filter(NULL, 123, env_in, filter);
	OSMO_ASSERT(rc < 0);

	printf("Testing for zero-length out\n");
	rc = osmo_environment_filter(out, 0, env_in, filter);
	OSMO_ASSERT(rc < 0);

	printf("Testing for one-length out\n");
	rc = osmo_environment_filter(out, 1, env_in, filter);
	OSMO_ASSERT(rc == 1 && out[0] == NULL);

	printf("Testing for no filter\n");
	rc = osmo_environment_filter(out, ARRAY_SIZE(out), env_in, NULL);
	OSMO_ASSERT(rc < 0);

	printf("Testing for no input\n");
	rc = osmo_environment_filter(out, ARRAY_SIZE(out), NULL, filter);
	OSMO_ASSERT(rc == 1 && out[0] == NULL);
	printf("Success!\n");
}

static void test_env_append(void)
{
	char *out[256] = {
		"FOO=a",
		"BAR=b",
		"BAZ=c",
		NULL,
	};
	char *add[] = {
		"MAHL=zeit",
		"GSM=global",
		"UMTS=universal",
		"LTE=evolved",
		NULL,
	};
	int rc;

	printf("\n==== osmo_environment_append ====\n");

	printf("Input Environment:\n");
	env_dump(out);
	printf("Input Addition:\n");
	env_dump(add);
	rc = osmo_environment_append(out, ARRAY_SIZE(out), add);
	printf("Output Environment (%d)\n", rc);
	env_dump(out);
	OSMO_ASSERT(rc == 8);
	printf("Success!\n");
}

static void test_close_fd(void)
{
	struct stat st;
	int fds[2];
	int rc;

	printf("\n==== osmo_close_all_fds_above ====\n");

	/* create some extra fds */
	rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	OSMO_ASSERT(rc == 0);

	rc = fstat(fds[0], &st);
	OSMO_ASSERT(rc == 0);

	osmo_close_all_fds_above(2);

	rc = fstat(fds[0], &st);
	OSMO_ASSERT(rc == -1 && errno == EBADF);
	rc = fstat(fds[1], &st);
	OSMO_ASSERT(rc == -1 && errno == EBADF);
	printf("Success!\n");
}

static void test_system_nowait(void)
{
	char *addl_env[] = {
		"MAHLZEIT=spaet",
		NULL
	};
	int rc, pid, i;

	printf("\n==== osmo_system_nowait ====\n");

	pid = osmo_system_nowait("env | grep MAHLZEIT 1>&2", osmo_environment_whitelist, addl_env);
	OSMO_ASSERT(pid > 0);
	for (i = 0; i < 10; i++) {
		sleep(1);
		rc = waitpid(pid, NULL, WNOHANG);
		if (rc == pid) {
			printf("Success!\n");
			return;
		}
	}
	printf("ERROR: child didn't terminate within 10s\n");
}

int main(int argc, char **argv)
{
	test_env_filter();
	test_env_append();
	test_close_fd();
	test_system_nowait();

	exit(0);
}

/*! \file cpu_sched_vty.c
 * Implementation to CPU / Threading / Scheduler properties from VTY configuration.
 */
/* (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPLv2+
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sched.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <inttypes.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>

/*! \addtogroup Tdef_VTY
 *
 * CPU Scheduling related VTY API.
 *
 * @{
 * \file cpu_sched_vty.c
 */

enum sched_vty_thread_id {
	SCHED_VTY_THREAD_SELF,
	SCHED_VTY_THREAD_ALL,
	SCHED_VTY_THREAD_ID,
	SCHED_VTY_THREAD_NAME,
	SCHED_VTY_THREAD_UNKNOWN,
};

struct cpu_affinity_it {
	struct llist_head entry;
	enum sched_vty_thread_id tid_type;
	char bufname[64];
	cpu_set_t *cpuset;
	size_t cpuset_size;
	bool delay;
};

struct sched_vty_opts {
	void *tall_ctx;
	int sched_rr_prio;
	struct llist_head cpu_affinity_li;
	pthread_mutex_t cpu_affinity_li_mutex;
};

static struct sched_vty_opts *sched_vty_opts;

static struct cmd_node sched_node = {
	L_CPU_SCHED_NODE,
	"%s(config-cpu-sched)# ",
	1,
};

/* returns number of configured CPUs in the system, or negative otherwise */
static int get_num_cpus() {
	static unsigned int num_cpus = 0;
	long ln;

	if (num_cpus)
		return num_cpus;

	/* This is expensive (goes across /sys, so let's do it only once. It is
	 * guaranteed it won't change during process span anyway). */
	ln = sysconf(_SC_NPROCESSORS_CONF);
	if (ln < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR, "sysconf(_SC_NPROCESSORS_CONF) failed: %s\n",
		     strerror(errno));
		return -1;
	}
	num_cpus = (unsigned int) ln;
	return num_cpus;
}

/* Parses string with CPU hex Affinity Mask, with right-most bit being CPU0, and
 * fills a cpuset of size cpuset_size.
 */
static int parse_cpu_hex_mask(const char *str, cpu_set_t *cpuset, size_t cpuset_size)
{
	int len = strlen(str);
	const char *ptr = str + len - 1;
	int cpu = 0;

	/* skip optional '0x' prefix format */
	if (len >= 2 && str[0] == '0' && str[1] == 'x')
		str += 2;
	CPU_ZERO_S(cpuset_size, cpuset);

	while (ptr >= str) {
		char c = *ptr;
		uint8_t val;

		if (c >= '0' && c <= '9') {
			val = c - '0';
		} else {
			c = (char)tolower((int)c);
			if (c >= 'a' && c <= 'f')
				val = c + (10 - 'a');
			else
				return -1;
		}
		if (val & 0x01)
			CPU_SET_S(cpu, cpuset_size, cpuset);
		if (val & 0x02)
			CPU_SET_S(cpu + 1, cpuset_size, cpuset);
		if (val & 0x04)
			CPU_SET_S(cpu + 2, cpuset_size, cpuset);
		if (val & 0x08)
			CPU_SET_S(cpu + 3, cpuset_size, cpuset);
		ptr--;
		cpu += 4;
	}

	return 0;
}

/* Generates a hexstring in str from cpuset of size cpuset_size */
static int generate_cpu_hex_mask(char *str, size_t str_buf_size,
				 cpu_set_t *cpuset, size_t cpuset_size)
{
	char *ptr = str;
	int cpu;
	bool first_nonzero_found = false;

	/* 2 char per byte, + '0x' prefix + '\0' */
	if (cpuset_size * 2 + 2 + 1 > str_buf_size)
		return -1;

	*ptr++ = '0';
	*ptr++ = 'x';

	for (cpu = cpuset_size*8 - 4; cpu >= 0; cpu -= 4) {
		uint8_t val = 0;

		if (CPU_ISSET_S(cpu, cpuset_size, cpuset))
			val |= 0x01;
		if (CPU_ISSET_S(cpu + 1, cpuset_size, cpuset))
			val |= 0x02;
		if (CPU_ISSET_S(cpu + 2, cpuset_size, cpuset))
			val |= 0x04;
		if (CPU_ISSET_S(cpu + 3, cpuset_size, cpuset))
			val |= 0x08;

		if (val < 10)
			*ptr = '0' + val;
		else
			*ptr = ('a' - 10) + val;
		if (val)
			first_nonzero_found = true;
		if (first_nonzero_found)
			ptr++;

	}
	if (!first_nonzero_found)
		*ptr++ = '0';
	*ptr = '\0';
	return 0;
}

/* Checks whther a thread identified by tid exists and belongs to the running process */
static bool proc_tid_exists(pid_t tid)
{
	DIR *proc_dir;
	struct dirent *entry;
	char dirname[100];
	int tid_it;
	bool found = false;

	snprintf(dirname, sizeof(dirname), "/proc/%ld/task", (long int)getpid());
	proc_dir = opendir(dirname);
	if (!proc_dir)
		return false; /*FIXME; print error */

	while ((entry = readdir(proc_dir))) {
		if (entry->d_name[0] == '.')
			continue;
		tid_it = atoi(entry->d_name);
		if (tid_it == tid) {
			found = true;
			break;
		}
	}

	closedir(proc_dir);
	return found;
}

/* Checks whther a thread identified by name exists and belongs to the running
 * process, and returns its disocevered TID in res_pid.
 */
static bool proc_name_exists(const char *name, pid_t *res_pid)
{
	DIR *proc_dir;
	struct dirent *entry;
	char path[100];
	char buf[17]; /* 15 + \n + \0 */
	int tid_it;
	int fd;
	pid_t mypid = getpid();
	bool found = false;
	int rc;

	*res_pid = 0;

	snprintf(path, sizeof(path), "/proc/%ld/task", (long int)mypid);
	proc_dir = opendir(path);
	if (!proc_dir)
		return false;

	while ((entry = readdir(proc_dir)))
	{
		if (entry->d_name[0] == '.')
			continue;

		tid_it = atoi(entry->d_name);
		snprintf(path, sizeof(path), "/proc/%ld/task/%ld/comm", (long int)mypid, (long int) tid_it);
		if ((fd = open(path, O_RDONLY)) == -1)
			continue;
		rc = read(fd, buf, sizeof(buf) - 1);
		if (rc >= 0) {
			/* Last may char contain a '\n', get rid of it */
			if (rc > 0 && buf[rc - 1] == '\n')
				buf[rc - 1] = '\0';
			else
				buf[rc] = '\0';
			if (strcmp(name, buf) == 0) {
				*res_pid = tid_it;
				found = true;
			}
		}
		close(fd);

		if (found)
			break;
	}

	closedir(proc_dir);
	return found;
}

/* Parse VTY THREADNAME variable, return its type and fill discovered res_pid if required */
static enum sched_vty_thread_id procname2pid(pid_t *res_pid, const char *str, bool applynow)
{
	size_t i, len;
	bool is_pid = true;

	if (strcmp(str, "all") == 0) {
		*res_pid = 0;
		return SCHED_VTY_THREAD_ALL;
	}

	if (strcmp(str, "self") == 0) {
		*res_pid = 0;
		return SCHED_VTY_THREAD_SELF;
	}

	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (!isdigit(str[i])) {
			is_pid = false;
			break;
		}
	}
	if (is_pid) {
		int64_t val;
		if (osmo_str_to_int64(&val, str, 0, 0, INT64_MAX))
			return SCHED_VTY_THREAD_UNKNOWN;
		*res_pid = (pid_t)val;
		if (*res_pid != val)
			return SCHED_VTY_THREAD_UNKNOWN;
		if (!applynow || proc_tid_exists(*res_pid))
			return SCHED_VTY_THREAD_ID;
		else
			return SCHED_VTY_THREAD_UNKNOWN;
	}

	if (len > 15) {
		/* Thread names only allow up to 15+1 null chars, see man pthread_setname_np */
		return SCHED_VTY_THREAD_UNKNOWN;
	}

	if (applynow) {
		if (proc_name_exists(str, res_pid))
			return SCHED_VTY_THREAD_NAME;
		else
			return SCHED_VTY_THREAD_UNKNOWN;
	} else  {
		/* assume a thread will be named after it */
		*res_pid = 0;
		return SCHED_VTY_THREAD_NAME;
	}
}

/* Wrapper for sched_setaffinity applying to single thread or all threads in process based on tid_type. */
static int my_sched_setaffinity(enum sched_vty_thread_id tid_type, pid_t pid,
				cpu_set_t *cpuset, size_t cpuset_size)
{
	DIR *proc_dir;
	struct dirent *entry;
	char dirname[100];
	char str_mask[1024];
	int tid_it;
	int rc = 0;

	if (generate_cpu_hex_mask(str_mask, sizeof(str_mask), cpuset, cpuset_size) < 0)
		str_mask[0] = '\0';

	if (tid_type != SCHED_VTY_THREAD_ALL) {
		LOGP(DLGLOBAL, LOGL_NOTICE, "Setting CPU affinity mask for tid %lu to: %s\n",
		     (unsigned long) pid, str_mask);

		rc = sched_setaffinity(pid, sizeof(cpu_set_t), cpuset);
		return rc;
	}

	snprintf(dirname, sizeof(dirname), "/proc/%ld/task", (long int)getpid());
	proc_dir = opendir(dirname);
	if (!proc_dir)
		return -EINVAL;

	while ((entry = readdir(proc_dir)))
	{
		if (entry->d_name[0] == '.')
			continue;
		tid_it = atoi(entry->d_name);
		LOGP(DLGLOBAL, LOGL_NOTICE, "Setting CPU affinity mask for tid %lu to: %s\n",
		     (unsigned long) tid_it, str_mask);

		rc = sched_setaffinity(tid_it, sizeof(cpu_set_t), cpuset);
		if (rc == -1)
			break;
	}

	closedir(proc_dir);
	return rc;

}

DEFUN_ATTR(cfg_sched_cpu_affinity, cfg_sched_cpu_affinity_cmd,
	"cpu-affinity (self|all|<0-4294967295>|THREADNAME) CPUHEXMASK [delay]",
	"Set CPU affinity mask on a (group of) thread(s)\n"
	"Set CPU affinity mask on thread running the VTY\n"
	"Set CPU affinity mask on all process' threads\n"
	"Set CPU affinity mask on a thread with specified PID\n"
	"Set CPU affinity mask on a thread with specified thread name\n"
	"CPU affinity mask\n"
	"If set, delay applying the affinity mask now and let the app handle it at a later point\n",
	CMD_ATTR_IMMEDIATE)
{
	const char* str_who = argv[0];
	const char *str_mask = argv[1];
	bool applynow = (argc != 3);
	int rc;
	pid_t pid;
	enum sched_vty_thread_id tid_type;
	struct cpu_affinity_it *it, *it_next;
	cpu_set_t *cpuset;
	size_t cpuset_size;

	tid_type = procname2pid(&pid, str_who, applynow);
	if (tid_type == SCHED_VTY_THREAD_UNKNOWN) {
		vty_out(vty, "%% Failed parsing target thread %s%s",
		        str_who, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (tid_type == SCHED_VTY_THREAD_ID && !applynow)  {
		vty_out(vty, "%% It makes no sense to delay applying cpu-affinity on tid %lu%s",
			(unsigned long)pid, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (tid_type == SCHED_VTY_THREAD_ALL && !applynow)  {
		vty_out(vty, "%% It makes no sense to delay applying cpu-affinity on all threads%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	cpuset = CPU_ALLOC(get_num_cpus());
	cpuset_size = CPU_ALLOC_SIZE(get_num_cpus());
	if (parse_cpu_hex_mask(str_mask, cpuset, cpuset_size) < 0) {
		vty_out(vty, "%% Failed parsing CPU Affinity Mask %s%s",
		    str_mask, VTY_NEWLINE);
		CPU_FREE(cpuset);
		return CMD_WARNING;
	}

	if (applynow) {
		rc = my_sched_setaffinity(tid_type, pid, cpuset, cpuset_size);
		if (rc == -1) {
			vty_out(vty, "%% Failed setting sched CPU Affinity Mask %s: %s%s",
				str_mask, strerror(errno), VTY_NEWLINE);
			CPU_FREE(cpuset);
			return CMD_WARNING;
		}
	}

	/* Keep history of cmds applied to be able to rewrite config. If PID was passed
	   directly it makes no sense to store it since PIDs are temporary */
	if (tid_type == SCHED_VTY_THREAD_SELF ||
	    tid_type == SCHED_VTY_THREAD_ALL ||
	    tid_type == SCHED_VTY_THREAD_NAME) {
		pthread_mutex_lock(&sched_vty_opts->cpu_affinity_li_mutex);

		/* Drop previous entries matching, since they will be overwritten */
		llist_for_each_entry_safe(it, it_next, &sched_vty_opts->cpu_affinity_li, entry) {
			if (strcmp(it->bufname, str_who) == 0) {
				llist_del(&it->entry);
				CPU_FREE(it->cpuset);
				talloc_free(it);
				break;
			}
		}
		it = talloc_zero(sched_vty_opts->tall_ctx, struct cpu_affinity_it);
		OSMO_STRLCPY_ARRAY(it->bufname, str_who);
		it->tid_type = tid_type;
		it->cpuset = cpuset;
		it->cpuset_size = cpuset_size;
		it->delay = !applynow;
		llist_add_tail(&it->entry, &sched_vty_opts->cpu_affinity_li);

		pthread_mutex_unlock(&sched_vty_opts->cpu_affinity_li_mutex);
	} else {
		/* We don't need cpuset for later, free it: */
		CPU_FREE(cpuset);
	}
	return CMD_SUCCESS;
}

static int set_sched_rr(unsigned int prio)
{
	struct sched_param param;
	int rc;
	memset(&param, 0, sizeof(param));
	param.sched_priority = prio;
	LOGP(DLGLOBAL, LOGL_NOTICE, "Setting SCHED_RR priority %d\n", param.sched_priority);
	rc = sched_setscheduler(getpid(), SCHED_RR, &param);
	if (rc == -1) {
		LOGP(DLGLOBAL, LOGL_ERROR, "Setting SCHED_RR priority %d failed: %s\n",
		     param.sched_priority, strerror(errno));
		return -1;
	}
	return 0;
}

DEFUN_ATTR(cfg_sched_policy, cfg_sched_policy_cmd,
	"policy rr <1-32>",
	"Set the scheduling policy to use for the process\n"
	"Use the SCHED_RR real-time scheduling algorithm\n"
	"Set the SCHED_RR real-time priority\n",
	CMD_ATTR_IMMEDIATE)
{
	sched_vty_opts->sched_rr_prio = atoi(argv[0]);

	if (set_sched_rr(sched_vty_opts->sched_rr_prio) < 0) {
		vty_out(vty, "%% Failed setting SCHED_RR priority %d%s",
			sched_vty_opts->sched_rr_prio, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sched,
      cfg_sched_cmd,
      "cpu-sched", "Configure CPU Scheduler related settings")
{
	vty->index = NULL;
	vty->node = L_CPU_SCHED_NODE;

	return CMD_SUCCESS;
}

DEFUN(show_sched_threads, show_sched_threads_cmd,
	"show cpu-sched threads",
	SHOW_STR
	"Show Sched section information\n"
	"Show information about running threads)\n")
{
	DIR *proc_dir;
	struct dirent *entry;
	char path[100];
	char name[17];
	char str_mask[1024];
	int tid_it;
	int fd;
	pid_t mypid = getpid();
	int rc;
	cpu_set_t *cpuset;
	size_t cpuset_size;

	vty_out(vty, "Thread list for PID %lu:%s", (unsigned long) mypid, VTY_NEWLINE);

	snprintf(path, sizeof(path), "/proc/%ld/task", (long int)mypid);
	proc_dir = opendir(path);
	if (!proc_dir) {
		vty_out(vty, "%% Failed opening dir%s%s", path, VTY_NEWLINE);
		return CMD_WARNING;
	}

	while ((entry = readdir(proc_dir)))
	{
		if (entry->d_name[0] == '.')
			continue;

		tid_it = atoi(entry->d_name);
		snprintf(path, sizeof(path), "/proc/%ld/task/%ld/comm", (long int)mypid, (long int)tid_it);
		if ((fd = open(path, O_RDONLY)) != -1) {
			rc = read(fd, name, sizeof(name) - 1);
			if (rc >= 0) {
				/* Last may char contain a '\n', get rid of it */
				if (rc > 0 && name[rc - 1] == '\n')
					name[rc - 1] = '\0';
				else
					name[rc] = '\0';
			}
			close(fd);
		} else {
			name[0] = '\0';
		}

		str_mask[0] = '\0';
		cpuset = CPU_ALLOC(get_num_cpus());
		cpuset_size = CPU_ALLOC_SIZE(get_num_cpus());
		CPU_ZERO_S(cpuset_size, cpuset);
		if (sched_getaffinity(tid_it, cpuset_size, cpuset) == 0) {
			if (generate_cpu_hex_mask(str_mask, sizeof(str_mask), cpuset, cpuset_size) < 0)
				str_mask[0] = '\0';
		}
		CPU_FREE(cpuset);

		vty_out(vty, " TID: %lu, NAME: '%s', cpu-affinity: %s%s",
			(unsigned long) tid_it, name, str_mask, VTY_NEWLINE);
	}

	closedir(proc_dir);
	return CMD_SUCCESS;
}

static int config_write_sched(struct vty *vty)
{
	struct cpu_affinity_it *it;
	char str_mask[1024];

	/* Only add the node if there's something to write under it */
	if (sched_vty_opts->sched_rr_prio || !llist_empty(&sched_vty_opts->cpu_affinity_li))
		vty_out(vty, "cpu-sched%s", VTY_NEWLINE);

	if (sched_vty_opts->sched_rr_prio)
		vty_out(vty, " policy rr %d%s", sched_vty_opts->sched_rr_prio, VTY_NEWLINE);

	llist_for_each_entry(it, &sched_vty_opts->cpu_affinity_li, entry) {
		if (generate_cpu_hex_mask(str_mask, sizeof(str_mask), it->cpuset, it->cpuset_size) < 0)
			OSMO_STRLCPY_ARRAY(str_mask, "ERROR");
		vty_out(vty, " cpu-affinity %s %s%s%s", it->bufname, str_mask,
			it->delay ? " delay" : "", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/*! Initialize sched VTY nodes
 * \param[in] tall_ctx  Talloc context to use internally by vty_sched subsystem.
 * \return 0 on success, non-zero on error.
 */
int osmo_cpu_sched_vty_init(void *tall_ctx)
{
	OSMO_ASSERT(!sched_vty_opts); /* assert only called once */

	sched_vty_opts = talloc_zero(tall_ctx, struct sched_vty_opts);
	sched_vty_opts->tall_ctx = tall_ctx;
	INIT_LLIST_HEAD(&sched_vty_opts->cpu_affinity_li);
	pthread_mutex_init(&sched_vty_opts->cpu_affinity_li_mutex, NULL);

	install_lib_element(CONFIG_NODE, &cfg_sched_cmd);
	install_node(&sched_node, config_write_sched);

	install_lib_element(L_CPU_SCHED_NODE, &cfg_sched_policy_cmd);
	install_lib_element(L_CPU_SCHED_NODE, &cfg_sched_cpu_affinity_cmd);

	install_lib_element_ve(&show_sched_threads_cmd);

	/* Initialize amount of cpus now */
	if (get_num_cpus() < 0)
		return -1;

	return 0;
}

/*! Apply cpu-affinity on calling thread based on VTY configuration
 * \return 0 on success, non-zero on error.
 */
int osmo_cpu_sched_vty_apply_localthread(void)
{
	struct cpu_affinity_it *it, *it_match = NULL;
	char name[16];  /* 15 + \0 */
	char str_mask[1024];
	bool has_name = false;
	int rc = 0;

	/* Assert subsystem was inited and structs are preset */
	if (!sched_vty_opts) {
		LOGP(DLGLOBAL, LOGL_FATAL, "Setting cpu-affinity mask impossible: no opts!\n");
		return 0;
	}

	if (pthread_getname_np(pthread_self(), name, sizeof(name)) == 0)
		has_name = true;

	/* Get latest matching mask for the thread */
	pthread_mutex_lock(&sched_vty_opts->cpu_affinity_li_mutex);
	llist_for_each_entry(it, &sched_vty_opts->cpu_affinity_li, entry) {
		switch (it->tid_type) {
		case SCHED_VTY_THREAD_SELF:
			continue; /* self to the VTY thread, not us */
		case SCHED_VTY_THREAD_ALL:
			it_match = it;
			break;
		case SCHED_VTY_THREAD_NAME:
			if (!has_name)
				continue;
			if (strcmp(name, it->bufname) != 0)
				continue;
			it_match = it;
			break;
		default:
			OSMO_ASSERT(0);
		}
	}

	if (it_match) {
		rc = my_sched_setaffinity(SCHED_VTY_THREAD_SELF, 0, it_match->cpuset, it_match->cpuset_size);
		if (rc == -1) {
			if (generate_cpu_hex_mask(str_mask, sizeof(str_mask),
						  it_match->cpuset, it_match->cpuset_size) < 0)
				str_mask[0] = '\0';
			LOGP(DLGLOBAL, LOGL_FATAL, "Setting cpu-affinity mask %s failed: %s\n",
			     str_mask, strerror(errno));
		}
	}
	pthread_mutex_unlock(&sched_vty_opts->cpu_affinity_li_mutex);
	return rc;
}

/*! @} */

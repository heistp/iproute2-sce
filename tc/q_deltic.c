// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/*
 * Delay Time Control (DelTiC)
 *
 * A family of qdiscs including:
 *  - POLYA, a basic leaf qdisc implementing just the AQM
 *  - ZERNO, a work-conserving qdisc with a policer-style AQM
 *  - BOROSHNE, an Approximate Fairness qdisc with delay-based flow classification
 *  - KHLIB, a full-featured Smart Queue Management solution
 *
 *  Copyright (C) 2014-2024 Jonathan Morton <chromatix99@gmail.com>
 *  Copyright (C) 2017-2018 Toke Høiland-Jørgensen <toke@toke.dk>
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>

#include "utils.h"
#include "tc_util.h"

static void polya_explain(void)
{
	fprintf(stderr,
		"Usage: ... deltic_polya [ sce-resonance FREQ | no-sce ] [ ecn-resonance FREQ | no-ecn ] [ drop-resonance FREQ | no-drop ]\n");
}

static int polya_parse_opt(struct qdisc_util *qu, int argc, char **argv,
				struct nlmsghdr *n, const char *dev)
{
	struct rtattr *tail;
	double sce_res = -1;
	double ecn_res = -1;
	double drop_res = -1;
	bool raw = 0;

	while (argc > 0) {
		if (strcmp(*argv, "no-sce") == 0)
			sce_res = 0;
		else if (strcmp(*argv, "no-ecn") == 0)
			ecn_res = 0;
		else if (strcmp(*argv, "no-drop") == 0)
			drop_res = 0;
		else if (strcmp(*argv, "sce-resonance") == 0) {
			NEXT_ARG();
			if (get_freq(&sce_res, *argv, &raw) || sce_res >= 65536) {
				fprintf(stderr, "Illegal \"sce_resonance\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "ecn-resonance") == 0) {
			NEXT_ARG();
			if (get_freq(&ecn_res, *argv, &raw) || ecn_res >= 65536) {
				fprintf(stderr, "Illegal \"ecn_resonance\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "drop-resonance") == 0) {
			NEXT_ARG();
			if (get_freq(&drop_res, *argv, &raw) || drop_res >= 65536) {
				fprintf(stderr, "Illegal \"drop_resonance\"\n");
				return -1;
			}
		} else {
			polya_explain();
			return -1;
		}
		argc--; argv++;
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS | NLA_F_NESTED, NULL, 0);

	/* frequencies supplied to DelTiC as 16.16 fixed-point */
	if (drop_res >= 0) {
		unsigned int v = drop_res * 65536;
		addattr_l(n, 1024, TCA_DELTIC_FREQ_DROP, &v, sizeof(v));
	}
	if (ecn_res >= 0) {
		unsigned int v = ecn_res * 65536;
		addattr_l(n, 1024, TCA_DELTIC_FREQ_ECN, &v, sizeof(v));
	}
	if (sce_res >= 0) {
		unsigned int v = sce_res * 65536;
		addattr_l(n, 1024, TCA_DELTIC_FREQ_SCE, &v, sizeof(v));
	}

	tail->rta_len = (void*) NLMSG_TAIL(n) - (void*) tail;
	return 0;
}

static int polya_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_DELTIC_MAX + 1];
	double v = 0;

//	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_DELTIC_MAX, opt);

	if (tb[TCA_DELTIC_FREQ_SCE] && RTA_PAYLOAD(tb[TCA_DELTIC_FREQ_SCE]) >= sizeof(__u32)) {
		v = rta_getattr_u32(tb[TCA_DELTIC_FREQ_SCE]) / 65536.0;
		if(!v)
			print_string(PRINT_ANY, "no_sce", "no-sce ", NULL);
		else
			print_double(PRINT_ANY, "sce_resonance", "sce-resonance %gHz ", v);
	}
	if (tb[TCA_DELTIC_FREQ_ECN] && RTA_PAYLOAD(tb[TCA_DELTIC_FREQ_ECN]) >= sizeof(__u32)) {
		v = rta_getattr_u32(tb[TCA_DELTIC_FREQ_ECN]) / 65536.0;
		if(!v)
			print_string(PRINT_ANY, "no_ecn", "no-ecn ", NULL);
		else
			print_double(PRINT_ANY, "ecn_resonance", "ecn-resonance %gHz ", v);
	}
	if (tb[TCA_DELTIC_FREQ_DROP] && RTA_PAYLOAD(tb[TCA_DELTIC_FREQ_DROP]) >= sizeof(__u32)) {
		v = rta_getattr_u32(tb[TCA_DELTIC_FREQ_DROP]) / 65536.0;
		if(!v)
			print_string(PRINT_ANY, "no_drop", "no-drop ", NULL);
		else
			print_double(PRINT_ANY, "drop_resonance", "drop-resonance %gHz ", v);
	}

	return 0;
}

//#define GET_STAT_S32(attr) (*(__s32 *)RTA_DATA(st[TCA_DELTIC_STATS_ ## attr]))
#define GET_STAT_U32(attr) rta_getattr_u32(st[TCA_DELTIC_STATS_ ## attr])
#define GET_STAT_U64(attr) rta_getattr_u64(st[TCA_DELTIC_STATS_ ## attr])

static int polya_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
	struct rtattr *st[TCA_DELTIC_STATS_MAX + 1];

	SPRINT_BUF(b1);

	if(xstats == NULL)
		return 0;

	parse_rtattr_nested(st, TCA_DELTIC_STATS_MAX, xstats);

	if (st[TCA_DELTIC_STATS_JITTER_EST]) {
		__u64 v = GET_STAT_U64(JITTER_EST);
		print_uint(PRINT_JSON, "jitter_est", NULL, v)
		print_string(PRINT_FP, NULL, " jitter estimate: %s", sprint_time(v, b1));
	}
	if (st[TCA_DELTIC_STATS_SCE_MARKS]) {
		print_uint(PRINT_ANY, "sce_marks", " SCE marks: ", GET_STAT_U64(SCE_MARKS));
	}
	if (st[TCA_DELTIC_STATS_CE_MARKS]) {
		print_uint(PRINT_ANY, "ce_marks", " CE marks: ", GET_STAT_U64(CE_MARKS));
	}
	if (st[TCA_DELTIC_STATS_AQM_DROPS]) {
		print_uint(PRINT_ANY, "aqm_drops", " AQM drops: ", GET_STAT_U64(AQM_DROPS));
	}

	return 0;
}

struct qdisc_util deltic_polya_qdisc_util = {
	.id		= "deltic_polya",
	.parse_qopt	= polya_parse_opt,
	.print_qopt	= polya_print_opt,
	.print_xstats	= polya_print_xstats,
};

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

typedef enum {
	POLYA = 1,
	ZERNO,
	BOROSHNE,
	KHLIB
} DelticVariant;

static void deltic_explain(DelticVariant var)
{
	if(var == POLYA) {
		fprintf(stderr,
			"Usage: ... deltic_polya [ sce-resonance FREQ | no-sce ] [ ecn-resonance FREQ | no-ecn ] [ drop-resonance FREQ | no-drop ]\n");
	} else if(var == BOROSHNE) {
		fprintf(stderr, "Usage: ... deltic_boroshne\n"
			"\t[ bandwidth RATE | unlimited* ] [ ptm | atm | noatm* ] [ overhead N | conservative | raw* ] [ mpu N ]\n"
			"\t[ sce-resonance FREQ | no-sce ] [ ecn-resonance FREQ | no-ecn ] [ drop-resonance FREQ | no-drop ]\n"
			);
	}
}

static int deltic_parse_opt(struct qdisc_util *qu, int argc, char **argv,
				struct nlmsghdr *n, const char *dev, DelticVariant var)
{
	struct rtattr *tail;
	double sce_res = -1;
	double ecn_res = -1;
	double drop_res = -1;
	bool raw = 0;

	__u64 bandwidth = 0;
	int unlimited = 0;
	bool overhead_override = false;
	bool overhead_set = false;
	int overhead = 0;
	int atm = -1;
	int mpu = 0;

	while (argc > 0) {
		// Start with universal DelTiC options
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

		// Shaper related options
		} else if(strcmp(*argv, "bandwidth") == 0) {
			NEXT_ARG();
			if (get_rate64(&bandwidth, *argv)) {
				fprintf(stderr, "Illegal \"bandwidth\"\n");
				return -1;
			}
			unlimited = 0;
		} else if(strcmp(*argv, "unlimited") == 0) {
			bandwidth = 0;
			unlimited = 1;
		} else if (strcmp(*argv, "ptm") == 0) {
			atm = CAKE_ATM_PTM;
		} else if (strcmp(*argv, "atm") == 0) {
			atm = CAKE_ATM_ATM;
		} else if (strcmp(*argv, "noatm") == 0) {
			atm = CAKE_ATM_NONE;
		} else if (strcmp(*argv, "raw") == 0) {
			atm = CAKE_ATM_NONE;
			overhead = 0;
			overhead_set = true;
			overhead_override = true;
		} else if (strcmp(*argv, "conservative") == 0) {
			/*
			 * Deliberately over-estimate overhead:
			 * one whole ATM cell plus ATM framing.
			 * A safe choice if the actual overhead is unknown.
			 */
			atm = CAKE_ATM_ATM;
			overhead = 48;
			overhead_set = true;

		/* Various ADSL framing schemes, all over ATM cells */
		} else if (strcmp(*argv, "ipoa-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 8;
			overhead_set = true;
		} else if (strcmp(*argv, "ipoa-llcsnap") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 16;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 24;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-llcsnap") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 32;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoa-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 10;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoa-llc") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 14;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoe-vcmux") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 32;
			overhead_set = true;
		} else if (strcmp(*argv, "pppoe-llcsnap") == 0) {
			atm = CAKE_ATM_ATM;
			overhead += 40;
			overhead_set = true;

		/* Typical VDSL2 framing schemes, both over PTM */
		/* PTM has 64b/65b coding which absorbs some bandwidth */
		} else if (strcmp(*argv, "pppoe-ptm") == 0) {
			/* 2B PPP + 6B PPPoE + 6B dest MAC + 6B src MAC
			 * + 2B ethertype + 4B Frame Check Sequence
			 * + 1B Start of Frame (S) + 1B End of Frame (Ck)
			 * + 2B TC-CRC (PTM-FCS) = 30B
			 */
			atm = CAKE_ATM_PTM;
			overhead += 30;
			overhead_set = true;
		} else if (strcmp(*argv, "bridged-ptm") == 0) {
			/* 6B dest MAC + 6B src MAC + 2B ethertype
			 * + 4B Frame Check Sequence
			 * + 1B Start of Frame (S) + 1B End of Frame (Ck)
			 * + 2B TC-CRC (PTM-FCS) = 22B
			 */
			atm = CAKE_ATM_PTM;
			overhead += 22;
			overhead_set = true;
		} else if (strcmp(*argv, "via-ethernet") == 0) {
			/*
			 * We used to use this flag to manually compensate for
			 * Linux including the Ethernet header on Ethernet-type
			 * interfaces, but not on IP-type interfaces.
			 *
			 * It is no longer needed, because Cake now adjusts for
			 * that automatically, and is thus ignored.
			 *
			 * It would be deleted entirely, but it appears in the
			 * stats output when the automatic compensation is
			 * active.
			 */
		} else if (strcmp(*argv, "ethernet") == 0) {
			/* ethernet pre-amble & interframe gap & FCS
			 * you may need to add vlan tag
			 */
			overhead += 38;
			overhead_set = true;
			mpu = 84;

		/* Additional Ethernet-related overhead used by some ISPs */
		} else if (strcmp(*argv, "ether-vlan") == 0) {
			/* 802.1q VLAN tag - may be repeated */
			overhead += 4;
			overhead_set = true;

		/*
		 * DOCSIS cable shapers account for Ethernet frame with FCS,
		 * but not interframe gap or preamble.
		 */
		} else if (strcmp(*argv, "docsis") == 0) {
			atm = CAKE_ATM_NONE;
			overhead += 18;
			overhead_set = true;
			mpu = 64;
		} else if (strcmp(*argv, "overhead") == 0) {
			char *p = NULL;

			NEXT_ARG();
			overhead = strtol(*argv, &p, 10);
			if (!p || *p || overhead < -64 || overhead > 120) {
				fprintf(stderr,
					"Illegal \"overhead\", valid range is -64 to 120\\n");
				return -1;
			}
			overhead_set = true;

		} else if (strcmp(*argv, "mpu") == 0) {
			char *p = NULL;

			NEXT_ARG();
			mpu = strtol(*argv, &p, 10);
			if (!p || *p || mpu < 0 || mpu > 256) {
				fprintf(stderr,
					"Illegal \"mpu\", valid range is 0 to 256\\n");
				return -1;
			}

		
		// Handle unrecognised options
		} else {
			if(strcmp(*argv, "help") != 0)
				fprintf(stderr, "What is \"%s\"?\n", *argv);
			deltic_explain(var);
			return -1;
		}
		argc--; argv++;
	}

	tail = NLMSG_TAIL(n);
	addattr(n, 1024, TCA_OPTIONS | NLA_F_NESTED);

	/* frequencies supplied to DelTiC as 16.16 fixed-point */
	if (drop_res >= 0)
		addattr32(n, 1024, TCA_DELTIC_FREQ_DROP, drop_res * 65536);
	if (ecn_res >= 0)
		addattr32(n, 1024, TCA_DELTIC_FREQ_ECN, ecn_res * 65536);
	if (sce_res >= 0)
		addattr32(n, 1024, TCA_DELTIC_FREQ_SCE, sce_res * 65536);

	/* Shaper related */
	if (var == POLYA) {
		/* POLYA doesn't support these options! */
		if(bandwidth || unlimited || atm != -1 || mpu > 0 || overhead_set || overhead_override) {
			fprintf(stderr, "Error: deltic_polya doesn't have a built-in shaper!\n");
			deltic_explain(var);
			return -1;
		}
	}
	if (bandwidth || unlimited)
		addattr64(n, 1024, TCA_DELTIC_BASE_RATE64, bandwidth);
	if (atm != -1)
		addattr8(n, 1024, TCA_DELTIC_ATM, atm);
	if (overhead_set)
		addattr8(n, 1024, TCA_DELTIC_OVERHEAD, overhead);
	if (overhead_override)
		addattr8(n, 1024, TCA_DELTIC_RAW, 1);
	if (mpu > 0)
		addattr16(n, 1024, TCA_DELTIC_MPU, mpu);

	tail->rta_len = (void*) NLMSG_TAIL(n) - (void*) tail;
	return 0;
}

static int deltic_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_DELTIC_MAX + 1];
	double v = 0;
	__u64 bandwidth = 0;
	int overhead = 0;
	int raw = 0;
	int mpu = 0;
	int atm = 0;

//	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_DELTIC_MAX, opt);

	// DelTiC parameters
	if (tb[TCA_DELTIC_FREQ_SCE] && RTA_PAYLOAD(tb[TCA_DELTIC_FREQ_SCE]) >= sizeof(__u32)) {
		v = rta_getattr_u32(tb[TCA_DELTIC_FREQ_SCE]) / 65536.0;
		if(!v)
			print_string(PRINT_ANY, "no_sce", "no-sce ", NULL);
		else
			print_float(PRINT_ANY, "sce_resonance", "sce-resonance %gHz ", v);
	}
	if (tb[TCA_DELTIC_FREQ_ECN] && RTA_PAYLOAD(tb[TCA_DELTIC_FREQ_ECN]) >= sizeof(__u32)) {
		v = rta_getattr_u32(tb[TCA_DELTIC_FREQ_ECN]) / 65536.0;
		if(!v)
			print_string(PRINT_ANY, "no_ecn", "no-ecn ", NULL);
		else
			print_float(PRINT_ANY, "ecn_resonance", "ecn-resonance %gHz ", v);
	}
	if (tb[TCA_DELTIC_FREQ_DROP] && RTA_PAYLOAD(tb[TCA_DELTIC_FREQ_DROP]) >= sizeof(__u32)) {
		v = rta_getattr_u32(tb[TCA_DELTIC_FREQ_DROP]) / 65536.0;
		if(!v)
			print_string(PRINT_ANY, "no_drop", "no-drop ", NULL);
		else
			print_float(PRINT_ANY, "drop_resonance", "drop-resonance %gHz ", v);
	}

	// Shaper parameters
	if (tb[TCA_DELTIC_BASE_RATE64] &&
	    RTA_PAYLOAD(tb[TCA_DELTIC_BASE_RATE64]) >= sizeof(bandwidth)) {
		bandwidth = rta_getattr_u64(tb[TCA_DELTIC_BASE_RATE64]);
		if (bandwidth)
			tc_print_rate(PRINT_ANY, "bandwidth", "bandwidth %s ",
				      bandwidth);
		else
			print_string(PRINT_ANY, "bandwidth", "bandwidth %s ",
				     "unlimited");
	}
	if (tb[TCA_DELTIC_ATM] &&
	    RTA_PAYLOAD(tb[TCA_DELTIC_ATM]) >= sizeof(__u8)) {
		atm = rta_getattr_u8(tb[TCA_DELTIC_ATM]);
	}
	if (tb[TCA_DELTIC_OVERHEAD] &&
	    RTA_PAYLOAD(tb[TCA_DELTIC_OVERHEAD]) >= sizeof(__s8)) {
		overhead = *(__s8 *) RTA_DATA(tb[TCA_DELTIC_OVERHEAD]);
	}
	if (tb[TCA_DELTIC_MPU] &&
	    RTA_PAYLOAD(tb[TCA_DELTIC_MPU]) >= sizeof(__u16)) {
		mpu = rta_getattr_u16(tb[TCA_DELTIC_MPU]);
	}
	if (tb[TCA_DELTIC_RAW]) {
		raw = 1;
	}

	if (raw) {
		print_string(PRINT_FP, NULL, "raw ", NULL);
		print_bool(PRINT_JSON, "raw", NULL, raw);
	}

	if (atm == CAKE_ATM_ATM)
		print_string(PRINT_ANY, "atm", "%s ", "atm");
	else if (atm == CAKE_ATM_PTM)
		print_string(PRINT_ANY, "atm", "%s ", "ptm");
	else if ((overhead || mpu) && !raw)
		print_string(PRINT_ANY, "atm", "%s ", "noatm");

	if(overhead)
		print_int(PRINT_ANY, "overhead", "overhead %d ", overhead);

	if (mpu)
		print_uint(PRINT_ANY, "mpu", "mpu %u ", mpu);

	return 0;
}

//#define GET_STAT_S32(attr) (*(__s32 *)RTA_DATA(st[TCA_DELTIC_STATS_ ## attr]))
#define GET_STAT_U32(attr) rta_getattr_u32(st[TCA_DELTIC_STATS_ ## attr])
#define GET_STAT_U64(attr) rta_getattr_u64(st[TCA_DELTIC_STATS_ ## attr])

static int deltic_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
	struct rtattr *st[TCA_DELTIC_STATS_MAX + 1];

	SPRINT_BUF(b1);

	if(xstats == NULL)
		return 0;

	parse_rtattr_nested(st, TCA_DELTIC_STATS_MAX, xstats);

	if (st[TCA_DELTIC_STATS_JITTER_EST]) {
		unsigned int v = GET_STAT_U32(JITTER_EST);
		print_uint(PRINT_JSON, "jitter_est", NULL, v);
		print_string(PRINT_FP, NULL, " jitter estimate: %s", sprint_time(v, b1));
	}
	if (st[TCA_DELTIC_STATS_SCE_MARKS]) {
		print_uint(PRINT_ANY, "sce_marks", " SCE marks: %lu", GET_STAT_U64(SCE_MARKS));
	}
	if (st[TCA_DELTIC_STATS_CE_MARKS]) {
		print_uint(PRINT_ANY, "ce_marks", " CE marks: %lu", GET_STAT_U64(CE_MARKS));
	}
	if (st[TCA_DELTIC_STATS_AQM_DROPS]) {
		print_uint(PRINT_ANY, "aqm_drops", " AQM drops: %lu", GET_STAT_U64(AQM_DROPS));
	}

	return 0;
}

static int polya_parse_opt(struct qdisc_util *qu, int argc, char **argv,
				struct nlmsghdr *n, const char *dev)
{
	return deltic_parse_opt(qu, argc, argv, n, dev, POLYA);
}

struct qdisc_util deltic_polya_qdisc_util = {
	.id		= "deltic_polya",
	.parse_qopt	= polya_parse_opt,
	.print_qopt	= deltic_print_opt,
	.print_xstats	= deltic_print_xstats,
};

static int boroshne_parse_opt(struct qdisc_util *qu, int argc, char **argv,
				struct nlmsghdr *n, const char *dev)
{
	return deltic_parse_opt(qu, argc, argv, n, dev, BOROSHNE);
}

struct qdisc_util deltic_boroshne_qdisc_util = {
	.id		= "deltic_boroshne",
	.parse_qopt	= boroshne_parse_opt,
	.print_qopt	= deltic_print_opt,
	.print_xstats	= deltic_print_xstats,
};

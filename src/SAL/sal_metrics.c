// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright 2024 Google LLC
 * Contributor : Yoni Couriel  yonic@google.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file sal_metrics.c
 * @brief SAL metrics module
 */

#include "sal_metrics.h"
#include "common_utils.h"
#include "nfs_convert.h"

/* Current number of confirmed clients gauge metric. */
static gauge_metric_handle_t confirmed_clients;

/* Clients lease expired event counter metric. */
static counter_metric_handle_t lease_expire_event_count;

/* Number of clients for each state-protection type */
static counter_metric_handle_t num_clients_per_state_protection[SP4_COUNT];

static gauge_metric_handle_t num_locks_metric[SAL_METRICS_LOCK_TYPE_COUNT];

/* Distribution of number of session-connections across sessions */
static histogram_metric_handle_t num_session_connections;
static int64_t session_connections_buckets[] = { 1,  2,	 4,  6,	 8,  10, 12,
						 14, 16, 18, 20, 24, 32 };

/* Number of denied session-and-xprt associations due to `dissociating` xprt */
static counter_metric_handle_t num_denied_session_xprt_associations;

/* Number of xprts per custom-data status */
static counter_metric_handle_t
	num_xprts_per_custom_data_status[XPRT_CUSTOM_DATA_STATUS_COUNT];

/* Distribution of number of xprt-sessions across xprts */
static histogram_metric_handle_t num_xprt_sessions;
static int64_t xprt_sessions_buckets[] = { 1, 2, 4, 6, 8, 10 };

/* Get strings corresponding to xprt_custom_data_status enum values */
static const char *get_xprt_custom_data_status(xprt_custom_data_status_t status)
{
	switch (status) {
	case ASSOCIATED_TO_XPRT:
		return "ASSOCIATED_TO_XPRT";
	case DISSOCIATED_FROM_XPRT:
		return "DISSOCIATED_FROM_XPRT";
	case DESTROYED:
		return "DESTROYED";
	default:
		LogFatal(COMPONENT_XPRT, "Unsupported xprt custom-data status");
	}
}

static void register_num_xprts_per_custom_data_status_metric(void)
{
	for (int i = 0; i < XPRT_CUSTOM_DATA_STATUS_COUNT; i++) {
		const metric_label_t labels[] = { METRIC_LABEL(
			"status", get_xprt_custom_data_status(i)) };

		num_xprts_per_custom_data_status[i] =
			monitoring__register_counter(
				"xprt__per_custom_data_status_count",
				METRIC_METADATA("Total number of xprts per "
						"custom-data status",
						METRIC_UNIT_NONE),
				labels, ARRAY_SIZE(labels));
	}
}

static void register_num_sessions_per_xprt_metric(void)
{
	const metric_label_t empty_labels[] = {};
	const histogram_buckets_t buckets = (histogram_buckets_t){
		.buckets = xprt_sessions_buckets,
		.count = ARRAY_SIZE(xprt_sessions_buckets)
	};

	num_xprt_sessions = monitoring__register_histogram(
		"xprt__sessions_count",
		METRIC_METADATA("Distribution of number of sessions "
				"associated with each xprt",
				METRIC_UNIT_NONE),
		empty_labels, ARRAY_SIZE(empty_labels), buckets);
}

/* Get strings corresponding to state_protectionion enum values */
static const char *get_state_protection_type(state_protect_how4 sp_how)
{
	switch (sp_how) {
	case SP4_NONE:
		return "SP4_NONE";
	case SP4_MACH_CRED:
		return "SP4_MACH_CRED";
	case SP4_SSV:
		return "SP4_SSV";
	default:
		LogFatal(COMPONENT_STATE, "Unsupported state protection");
	}
}

static void register_num_clients_per_state_protection_metric(void)
{
	for (int i = 0; i < SP4_COUNT; i++) {
		const metric_label_t sp_labels[] = { METRIC_LABEL(
			"sp_how", get_state_protection_type(i)) };

		num_clients_per_state_protection[i] =
			monitoring__register_counter(
				"clients__per_state_protection_count",
				METRIC_METADATA("Total number of clients per "
						"state-protection type",
						METRIC_UNIT_NONE),
				sp_labels, ARRAY_SIZE(sp_labels));
	}
}

static void register_client_metrics(void)
{
	const metric_label_t empty_labels[] = {};
	const char *const lock_type_string[SAL_METRICS_LOCK_TYPE_COUNT] = {
		"holders", "waiters"
	};

	confirmed_clients = monitoring__register_gauge(
		"clients__confirmed_count",
		METRIC_METADATA("Total Number of Confirmed Clients",
				METRIC_UNIT_NONE),
		empty_labels, ARRAY_SIZE(empty_labels));

	lease_expire_event_count = monitoring__register_counter(
		"clients__lease_expire_count",
		METRIC_METADATA("Total Number of Clients Lease Expired Events",
				METRIC_UNIT_NONE),
		empty_labels, ARRAY_SIZE(empty_labels));

	for (sal_metrics__lock_type lock_type = 0;
	     lock_type < SAL_METRICS_LOCK_TYPE_COUNT; lock_type++) {
		const metric_label_t lock_count_labels[] = { METRIC_LABEL(
			"lock_type", lock_type_string[lock_type]) };
		num_locks_metric[lock_type] = monitoring__register_gauge(
			"locks__count",
			METRIC_METADATA("Total Number of Locks Record Count",
					METRIC_UNIT_NONE),
			lock_count_labels, ARRAY_SIZE(lock_count_labels));
	}

	register_num_clients_per_state_protection_metric();
}

static void register_num_session_connections_metric(void)
{
	const metric_label_t empty_labels[] = {};
	const histogram_buckets_t buckets = (histogram_buckets_t){
		.buckets = session_connections_buckets,
		.count = ARRAY_SIZE(session_connections_buckets)
	};

	num_session_connections = monitoring__register_histogram(
		"session__connections_count",
		METRIC_METADATA("Distribution of number of "
				"session-connections across sessions",
				METRIC_UNIT_NONE),
		empty_labels, ARRAY_SIZE(empty_labels), buckets);
}

static void register_num_denied_session_xprt_associations_metric(void)
{
	const metric_label_t empty_labels[] = {};

	num_denied_session_xprt_associations = monitoring__register_counter(
		"session__denied_xprt_associations_count",
		METRIC_METADATA("Total number of denied session-and-xprt "
				"associations across sessions",
				METRIC_UNIT_NONE),
		empty_labels, ARRAY_SIZE(empty_labels));
}

void sal_metrics__confirmed_clients(int64_t num)
{
	monitoring__gauge_set(confirmed_clients, num);
}

void sal_metrics__lease_expire(void)
{
	monitoring__counter_inc(lease_expire_event_count, 1);
}

void sal_metrics__client_state_protection(state_protect_how4 sp)
{
	monitoring__counter_inc(num_clients_per_state_protection[sp], 1);
}

void sal_metrics__locks_inc(sal_metrics__lock_type lock_type)
{
	monitoring__gauge_inc(num_locks_metric[lock_type], 1);
}

void sal_metrics__locks_dec(sal_metrics__lock_type lock_type)
{
	monitoring__gauge_dec(num_locks_metric[lock_type], 1);
}

void sal_metrics__session_connections(int64_t num)
{
	monitoring__histogram_observe(num_session_connections, num);
}

void sal_metrics__xprt_association_denied(void)
{
	monitoring__counter_inc(num_denied_session_xprt_associations, 1);
}

void sal_metrics__xprt_custom_data_status(xprt_custom_data_status_t status)
{
	monitoring__counter_inc(num_xprts_per_custom_data_status[status], 1);
}

void sal_metrics__xprt_sessions(int64_t num)
{
	monitoring__histogram_observe(num_xprt_sessions, num);
}

void sal_metrics__init(void)
{
	register_client_metrics();
	register_num_session_connections_metric();
	register_num_denied_session_xprt_associations_metric();
	register_num_xprts_per_custom_data_status_metric();
	register_num_sessions_per_xprt_metric();
}

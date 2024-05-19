/* SPDX-License-Identifier: LGPL-3.0-or-later */
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
 * @file sal_metrics.h
 * @brief SAL metrics module
 */

#ifndef SAL_METRICS_H
#define SAL_METRICS_H

#include "monitoring.h"
#include "nfsv41.h"
#include "xprt_handler.h"

typedef enum sal_metrics__lock_type {
	SAL_METRICS_HOLDERS = 0,
	SAL_METRICS_WAITERS,
	SAL_METRICS_LOCK_TYPE_COUNT,
} sal_metrics__lock_type;

/* Total Number of Confirmed Clients */
void sal_metrics__confirmed_clients(int64_t num);
/* Total Number of Clients Lease Expired Events */
void sal_metrics__lease_expire(void);
/* Total number of clients per state-protection type */
void sal_metrics__client_state_protection(state_protect_how4);
/* Total Number of Locks Record Count */
void sal_metrics__locks_inc(sal_metrics__lock_type);
void sal_metrics__locks_dec(sal_metrics__lock_type);
/* Distribution of number of session-connections across sessions */
void sal_metrics__session_connections(int64_t num);
/* Total number of denied session-and-xprt associations across sessions */
void sal_metrics__xprt_association_denied(void);
/* Total number of xprts per custom-data status */
void sal_metrics__xprt_custom_data_status(xprt_custom_data_status_t);
/* Distribution of number of sessions associated with each xprt */
void sal_metrics__xprt_sessions(int64_t num);

void sal_metrics__init(void);

#endif /* !SAL_METRICS_H */

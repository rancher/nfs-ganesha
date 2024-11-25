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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
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
 * @file connection_manager.c
 * @brief Allows a client to be connected to a single Ganesha server at a time.
 */

#include "connection_manager.h"
#include "connection_manager_metrics.h"
#include "client_mgr.h"
#include "gsh_config.h"
#include "xprt_handler.h"

#include "gsh_lttng/gsh_lttng.h"
#if defined(USE_LTTNG) && !defined(LTTNG_PARSING)
#include "gsh_lttng/generated_traces/connection_manager.h"
#endif

#define LogDebugClient(client, format, args...) \
	LogDebug(COMPONENT_XPRT, "%s: " format, \
		 get_client_address_for_debugging(client), ##args)
#define LogInfoClient(client, format, args...) \
	LogInfo(COMPONENT_XPRT, "%s: " format, \
		get_client_address_for_debugging(client), ##args)
#define LogWarnClient(client, format, args...) \
	LogWarn(COMPONENT_XPRT, "%s: " format, \
		get_client_address_for_debugging(client), ##args)
#define LogFatalClient(client, format, args...) \
	LogFatal(COMPONENT_XPRT, "%s: " format, \
		 get_client_address_for_debugging(client), ##args)
#define LogDebugConnection(connection, format, args...)               \
	LogDebugClient(&(connection)->gsh_client->connection_manager, \
		       "fd %d: " format, (connection)->xprt->xp_fd, ##args)
#define LogInfoConnection(connection, format, args...)               \
	LogInfoClient(&(connection)->gsh_client->connection_manager, \
		      "fd %d: " format, (connection)->xprt->xp_fd, ##args)
#define LogWarnConnection(connection, format, args...)               \
	LogWarnClient(&(connection)->gsh_client->connection_manager, \
		      "fd %d: " format, (connection)->xprt->xp_fd, ##args)
#define LogFatalConnection(connection, format, args...)               \
	LogFatalClient(&(connection)->gsh_client->connection_manager, \
		       "fd %d: " format, (connection)->xprt->xp_fd, ##args)

#define PROV_NAME connection_manager
#define CLIENT_FORMAT "{}"
#define CLIENT_VARS(client, addr) TP_STR(addr)

#define CLIENT_AUTO_TRACEPOINT(client, event, log_level, format, ...)          \
	do {                                                                   \
		const char *const addr =                                       \
			get_client_address_for_debugging(client);              \
		GSH_AUTO_TRACEPOINT(PROV_NAME, event, log_level,               \
				    CLIENT_FORMAT ": " format,                 \
				    CLIENT_VARS(client, addr), ##__VA_ARGS__); \
	} while (0)

#define CONN_FORMAT "fd {}"
#define CONN_VARS(connection) (connection)->xprt->xp_fd

#define CONN_AUTO_TRACEPOINT(connection, event, log_level, format, ...)       \
	CLIENT_AUTO_TRACEPOINT(&(connection)->gsh_client->connection_manager, \
			       event, log_level, CONN_FORMAT ": " format,     \
			       CONN_VARS(connection), ##__VA_ARGS__)

static inline const char *
get_client_address_for_debugging(const connection_manager__client_t *client)
{
	const struct gsh_client *const gsh_client =
		container_of(client, struct gsh_client, connection_manager);
	return gsh_client->hostaddr_str;
}

static inline const sockaddr_t *
get_client_address(const connection_manager__client_t *client)
{
	const struct gsh_client *const gsh_client =
		container_of(client, struct gsh_client, connection_manager);
	return &gsh_client->cl_addrbuf;
}

static inline struct timespec timeout_seconds(uint32_t seconds)
{
	return (struct timespec){ .tv_sec = time(NULL) + seconds,
				  .tv_nsec = 0 };
}

static inline bool
is_transition_valid(enum connection_manager__client_state_t from,
		    enum connection_manager__client_state_t to)
{
	switch (from) {
	case CONNECTION_MANAGER__CLIENT_STATE__DRAINED:
		return to == CONNECTION_MANAGER__CLIENT_STATE__ACTIVATING;
	case CONNECTION_MANAGER__CLIENT_STATE__ACTIVATING:
		return to == CONNECTION_MANAGER__CLIENT_STATE__ACTIVE ||
		       to == CONNECTION_MANAGER__CLIENT_STATE__DRAINED;
	case CONNECTION_MANAGER__CLIENT_STATE__ACTIVE:
		return to == CONNECTION_MANAGER__CLIENT_STATE__DRAINING;
	case CONNECTION_MANAGER__CLIENT_STATE__DRAINING:
		return to == CONNECTION_MANAGER__CLIENT_STATE__ACTIVE ||
		       to == CONNECTION_MANAGER__CLIENT_STATE__DRAINED;
	default:
		return false;
	}
}

/* Assumes the client mutex is held */
static inline void
change_state(connection_manager__client_t *client,
	     enum connection_manager__client_state_t new_state)
{
	LogDebugClient(client, "Changing state: %d -> %d", client->state,
		       new_state);
	CLIENT_AUTO_TRACEPOINT(client, change_state, TRACE_INFO,
			       "Changing state: {} -> {}", client->state,
			       new_state);
	assert(is_transition_valid(client->state, new_state));
	connection_manager_metrics__client_state_inc(new_state);
	connection_manager_metrics__client_state_dec(client->state);
	client->state = new_state;
	PTHREAD_COND_broadcast(&client->cond_change);
}

/* Assumes the client mutex is held */
static inline void condition_wait(connection_manager__client_t *client)
{
	PTHREAD_COND_wait(&client->cond_change, &client->mutex);
}

enum condition_wait_t {
	CONDITION_WAIT__OK = 0,
	CONDITION_WAIT__TIMEOUT,
};

/* Assumes the client mutex is held */
static inline enum condition_wait_t
condition_timedwait(connection_manager__client_t *client,
		    struct timespec timeout)
{
	const int rc = pthread_cond_timedwait(&client->cond_change,
					      &client->mutex, &timeout);
	switch (rc) {
	case 0:
		return CONDITION_WAIT__OK;
	case ETIMEDOUT:
		return CONDITION_WAIT__TIMEOUT;
	default:
		CLIENT_AUTO_TRACEPOINT(client, cond_time, TRACE_CRIT,
				       "Unexpected return code: {}", rc);
		LogFatalClient(client, "Unexpected return code: %d", rc);
	}
}

/* Assumes the client mutex is held */
static inline void wait_for_state_change(connection_manager__client_t *client)
{
	const enum connection_manager__client_state_t initial_state =
		client->state;
	LogDebugClient(client, "Waiting until state changes from %d",
		       initial_state);
	CLIENT_AUTO_TRACEPOINT(client, wait_state_change, TRACE_INFO,
			       "Waiting until state changes from {}",
			       initial_state);
	while (client->state == initial_state)
		condition_wait(client);
}

static enum connection_manager__drain_t callback_default_drain_other_servers(
	void *context, const sockaddr_t *client_address,
	const char *client_address_str, const struct timespec *timeout)
{
	LogWarn(COMPONENT_XPRT,
		"%s: Client connected before Connection Manager callback was registered",
		client_address_str);
	GSH_AUTO_TRACEPOINT(PROV_NAME, default_drain, TRACE_WARNING,
			    "{}: Connection is not managed",
			    TP_STR(client_address_str));
	return CONNECTION_MANAGER__DRAIN__FAILED;
}

#define DEFAULT_CALLBACK_CONTEXT                     \
	{ /*user_context=*/                          \
	  NULL, callback_default_drain_other_servers \
	}

static pthread_rwlock_t callback_lock = RWLOCK_INITIALIZER;
static const connection_manager__callback_context_t callback_default =
	DEFAULT_CALLBACK_CONTEXT;
static connection_manager__callback_context_t callback_context =
	DEFAULT_CALLBACK_CONTEXT;

void connection_manager__callback_set(connection_manager__callback_context_t new)
{
	PTHREAD_RWLOCK_wrlock(&callback_lock);
	assert(callback_context.drain_and_disconnect_other_servers ==
	       callback_default.drain_and_disconnect_other_servers);
	callback_context = new;
	PTHREAD_RWLOCK_unlock(&callback_lock);
}

connection_manager__callback_context_t connection_manager__callback_clear(void)
{
	PTHREAD_RWLOCK_wrlock(&callback_lock);
	assert(callback_context.drain_and_disconnect_other_servers !=
	       callback_default.drain_and_disconnect_other_servers);
	const connection_manager__callback_context_t old = callback_context;
	callback_context = callback_default;
	PTHREAD_RWLOCK_unlock(&callback_lock);
	return old;
}

void connection_manager__client_init(connection_manager__client_t *client)
{
	LogDebugClient(client, "Client init %p", client);
	CLIENT_AUTO_TRACEPOINT(client, client_init, TRACE_INFO,
			       "Client init {}", client);
	client->state = CONNECTION_MANAGER__CLIENT_STATE__DRAINED;
	PTHREAD_MUTEX_init(&client->mutex, NULL);
	PTHREAD_COND_init(&client->cond_change, NULL);
	glist_init(&client->connections);
	client->connections_count = 0;
	connection_manager_metrics__client_state_inc(client->state);
}

void connection_manager__client_fini(connection_manager__client_t *client)
{
	LogDebugClient(client, "Client fini %p", client);
	CLIENT_AUTO_TRACEPOINT(client, client_fini, TRACE_INFO,
			       "Client fini {}", client);
	assert(client->connections_count == 0);
	assert(glist_empty(&client->connections));
	assert(client->state == CONNECTION_MANAGER__CLIENT_STATE__DRAINED);
	connection_manager_metrics__client_state_dec(client->state);
	PTHREAD_MUTEX_destroy(&client->mutex);
	PTHREAD_COND_destroy(&client->cond_change);
}

static void
update_socket_linger(const connection_manager__connection_t *connection)
{
	/* Setting Timeout=0, so the TCP connection will send RST on close()
	 * without waiting for the client's response. This is needed in case
	 * the client was migrated by a load balancer to another server, and
	 * we want the connection to close quickly.
	 * Linger is still enabled, so close() will block until the connection
	 * is closed. */
	const struct linger linger = { .l_onoff = 1, .l_linger = 0 };

	if (setsockopt(connection->xprt->xp_fd, SOL_SOCKET, SO_LINGER, &linger,
		       sizeof(linger)) < 0) {
		const char *const strerr = strerror(errno);
		LogWarnConnection(connection,
				  "Could not set linger for connection: %s",
				  strerr);
		CONN_AUTO_TRACEPOINT(connection, socket_linger, TRACE_WARNING,
				     "Could not set linger for connection: {}",
				     TP_STR(strerr));
	}
}

/* Assumes the client mutex is held */
static enum connection_manager__drain_t
try_drain_self(connection_manager__client_t *client, uint32_t timeout_sec)
{
	assert(client->state == CONNECTION_MANAGER__CLIENT_STATE__ACTIVE);
	change_state(client, CONNECTION_MANAGER__CLIENT_STATE__DRAINING);

	/* TODO: Extends client state lease (see explanation in header) */

	const struct glist_head *node;
	/* start draining connections */
	glist_for_each(node, &client->connections)
	{
		connection_manager__connection_t *const connection =
			glist_entry(node, connection_manager__connection_t,
				    node);
		LogDebugConnection(connection,
				   "Destroying connection (xp_refcnt %d)",
				   connection->xprt->xp_refcnt);
		CONN_AUTO_TRACEPOINT(connection, try_drain_self_entry,
				     TRACE_INFO,
				     "Destroying connection (xp_refcnt {})",
				     connection->xprt->xp_refcnt);
		assert(connection->is_managed);
		if (connection->is_destroyed)
			continue;
		connection->is_destroyed = true;
		update_socket_linger(connection);
		SVC_DESTROY(connection->xprt);
		connection->destroy_start = time(NULL);
	}
	LogDebugClient(client,
		       "Waiting for %d connections to terminate, timeout=%d",
		       client->connections_count, timeout_sec);
	CLIENT_AUTO_TRACEPOINT(
		client, try_drain_self_wait, TRACE_INFO,
		"Waiting for {} connections to terminate, timeout={}",
		client->connections_count, timeout_sec);
	const struct timespec timeout = timeout_seconds(timeout_sec);
	enum condition_wait_t wait_result = CONDITION_WAIT__OK;

	while (client->connections_count != 0 &&
	       client->state == CONNECTION_MANAGER__CLIENT_STATE__DRAINING) {
		/* Note mutex is temporarily released while waiting, and other
		 * threads can abort the draining */
		if (condition_timedwait(client, timeout) ==
		    CONDITION_WAIT__TIMEOUT) {
			wait_result = CONDITION_WAIT__TIMEOUT;
			break;
		}
	}
	LogDebugClient(client,
		       "Finished waiting: state=%d connections=%d wait=%d",
		       client->state, client->connections_count, wait_result);
	CLIENT_AUTO_TRACEPOINT(
		client, try_drain_self_finish_wait, TRACE_INFO,
		"Finished waiting: state={} connections={} wait={}",
		client->state, client->connections_count, wait_result);

	if (client->state == CONNECTION_MANAGER__CLIENT_STATE__DRAINING) {
		/* Since we have (mutex && DRAINING), we're allowed to change
		 * the state to DRAINED/ACTIVE. This also holds in more complex
		 * scenarios where the draining was aborted by another thread
		 * and then restarted by a third thread. */
		if (client->connections_count == 0) {
			change_state(client,
				     CONNECTION_MANAGER__CLIENT_STATE__DRAINED);
		} else {
			change_state(client,
				     CONNECTION_MANAGER__CLIENT_STATE__ACTIVE);
		}
	}

	if (client->state == CONNECTION_MANAGER__CLIENT_STATE__DRAINED) {
		return CONNECTION_MANAGER__DRAIN__SUCCESS;
	}

	/* Check for stuck connections */
	glist_for_each(node, &client->connections)
	{
		const connection_manager__connection_t *const connection =
			glist_entry(node, connection_manager__connection_t,
				    node);
		const int delta = time(NULL) - connection->destroy_start;
		const int max_delta =
			nfs_param.core_param.connection_manager_timeout_sec *
			CONNECTION_MANAGER__DRAIN_MAX_EXPECTED_ITERATIONS;
		/* Must check for "is_destroyed", because this might be a new
		   connection that aborted the drain. */
		if (connection->is_destroyed && delta > max_delta) {
			LogWarnConnection(connection, "Stuck for %d", delta);
			CONN_AUTO_TRACEPOINT(connection, try_drain_self_stuck,
					     TRACE_WARNING, "Stuck for {}",
					     delta);
			return CONNECTION_MANAGER__DRAIN__FAILED_STUCK;
		}
	}

	return wait_result == CONDITION_WAIT__TIMEOUT ?
		       CONNECTION_MANAGER__DRAIN__FAILED_TIMEOUT :
		       CONNECTION_MANAGER__DRAIN__FAILED;
}

enum connection_manager__drain_t
connection_manager__drain_and_disconnect_local(sockaddr_t *client_address)
{
	enum connection_manager__drain_t result;
	struct timespec start_time;

	now(&start_time);
	struct gsh_client *const gsh_client =
		get_gsh_client(client_address, /*lookup_only=*/true);
	if (gsh_client == NULL) {
		if (isDebug(COMPONENT_XPRT)) {
			char address_for_debugging[SOCK_NAME_MAX];
			bool ok;

			ok = sprint_sockip(client_address,
					   address_for_debugging,
					   sizeof(address_for_debugging));

			LogDebug(COMPONENT_XPRT, "Client not found: %s",
				 ok ? address_for_debugging : "<unknown>");
			GSH_AUTO_TRACEPOINT(PROV_NAME, disco_local_no_client,
					    TRACE_INFO, "Client not found: {}",
					    TP_STR(ok ? address_for_debugging :
							"<unknown>"));
		}
		result = CONNECTION_MANAGER__DRAIN__SUCCESS_NO_CONNECTIONS;
		goto out;
	}
	connection_manager__client_t *const client =
		&gsh_client->connection_manager;

	PTHREAD_MUTEX_lock(&client->mutex);
	switch (client->state) {
	case CONNECTION_MANAGER__CLIENT_STATE__DRAINED: {
		LogDebugClient(client, "Already drained");
		CLIENT_AUTO_TRACEPOINT(client, disco_local_drained, TRACE_INFO,
				       "Already drained");
		result = CONNECTION_MANAGER__DRAIN__SUCCESS_NO_CONNECTIONS;
		break;
	}
	case CONNECTION_MANAGER__CLIENT_STATE__ACTIVATING: {
		LogDebugClient(client, "Busy draining other servers");
		CLIENT_AUTO_TRACEPOINT(client, disco_local_activating,
				       TRACE_INFO,
				       "Busy draining other servers");
		result = CONNECTION_MANAGER__DRAIN__FAILED;
		break;
	}
	case CONNECTION_MANAGER__CLIENT_STATE__ACTIVE: {
		LogDebugClient(client, "Starting self drain");
		CLIENT_AUTO_TRACEPOINT(client, disco_local_active, TRACE_INFO,
				       "Starting self drain");
		result = try_drain_self(
			client,
			nfs_param.core_param.connection_manager_timeout_sec);
		break;
	}
	case CONNECTION_MANAGER__CLIENT_STATE__DRAINING: {
		LogDebugClient(client, "Already self draining, waiting");
		CLIENT_AUTO_TRACEPOINT(client, disco_local_draining, TRACE_INFO,
				       "Already self draining, waiting");
		wait_for_state_change(client);
		result = (client->state ==
			  CONNECTION_MANAGER__CLIENT_STATE__DRAINED) ?
				 CONNECTION_MANAGER__DRAIN__SUCCESS :
				 CONNECTION_MANAGER__DRAIN__FAILED;
		break;
	}
	default: {
		CLIENT_AUTO_TRACEPOINT(client, disco_local_state_unknown,
				       TRACE_CRIT,
				       "Unexpected connection manager state {}",
				       client->state);
		LogFatalClient(client, "Unexpected connection manager state %d",
			       client->state);
	}
	}

	PTHREAD_MUTEX_unlock(&client->mutex);
	put_gsh_client(gsh_client);

	switch (result) {
	case CONNECTION_MANAGER__DRAIN__SUCCESS:
		/* Fallthrough */
	case CONNECTION_MANAGER__DRAIN__SUCCESS_NO_CONNECTIONS:
		LogDebugClient(client, "Drain was successful: %d", result);
		CLIENT_AUTO_TRACEPOINT(client, disco_local_no_connections,
				       TRACE_INFO, "Drain was successful: {}",
				       result);
		break;
	case CONNECTION_MANAGER__DRAIN__FAILED:
		/* Fallthrough */
	case CONNECTION_MANAGER__DRAIN__FAILED_TIMEOUT:
		/* Fallthrough */
	case CONNECTION_MANAGER__DRAIN__FAILED_STUCK:
		LogWarnClient(client, "Drain failed: %d", result);
		CLIENT_AUTO_TRACEPOINT(client, disco_local_failed_stuc,
				       TRACE_INFO, "Drain failed: {}", result);
		break;
	default:
		CLIENT_AUTO_TRACEPOINT(client, disco_local_result_unknown,
				       TRACE_CRIT, "Unknown result: {}",
				       result);
		LogFatalClient(client, "Unknown result: %d", result);
	}

out:
	connection_manager_metrics__drain_local_client_done(result,
							    &start_time);
	return result;
}

static inline connection_manager__connection_t *
xprt_to_connection(const SVCXPRT *xprt)
{
	if (xprt->xp_u1 == NULL) {
		LogInfo(COMPONENT_XPRT, "fd %d: No custom data allocated",
			xprt->xp_fd);
		GSH_AUTO_TRACEPOINT(PROV_NAME, xprt_to_conn, TRACE_INFO,
				    "fd {}: No custom data allocated",
				    xprt->xp_fd);
		return NULL;
	}
	xprt_custom_data_t *const xprt_data = (xprt_custom_data_t *)xprt->xp_u1;
	return &xprt_data->managed_connection;
}

static inline bool should_manage_connection(sockaddr_t *client_address)
{
	return nfs_param.core_param.enable_connection_manager &&
	       !is_loopback(client_address);
}

static inline bool is_drain_success(enum connection_manager__drain_t result)
{
	return result == CONNECTION_MANAGER__DRAIN__SUCCESS ||
	       result == CONNECTION_MANAGER__DRAIN__SUCCESS_NO_CONNECTIONS;
}

/**
 * Tries to activate the client if it's not already activated.
 * The "connection" parameter is used for logging purposes only, the entity
 * being activated is the client.
 *
 * Assumes the client mutex is held.
 */
static void
try_activate_client_if_needed(connection_manager__connection_t *connection)
{
	connection_manager__client_t *const client =
		&connection->gsh_client->connection_manager;

	switch (client->state) {
	case CONNECTION_MANAGER__CLIENT_STATE__DRAINED: {
		LogDebugConnection(connection, "Client is drained, activating");
		CONN_AUTO_TRACEPOINT(connection, activate_clinet__drained,
				     TRACE_INFO,
				     "Client is drained, activating");
		change_state(client,
			     CONNECTION_MANAGER__CLIENT_STATE__ACTIVATING);
		/* It's OK to unlock because no other thread can change the
		 * state while ACTIVATING. */
		PTHREAD_MUTEX_unlock(&client->mutex);

		LogDebugConnection(connection, "Draining other servers");
		CONN_AUTO_TRACEPOINT(connection, activate_clinet__drain_others,
				     TRACE_INFO, "Draining other servers");
		const struct timespec timeout = timeout_seconds(
			nfs_param.core_param.connection_manager_timeout_sec);
		PTHREAD_RWLOCK_rdlock(&callback_lock);
		const enum connection_manager__drain_t drain_result =
			callback_context.drain_and_disconnect_other_servers(
				callback_context.user_context,
				get_client_address(client),
				get_client_address_for_debugging(client),
				&timeout);
		PTHREAD_RWLOCK_unlock(&callback_lock);

		PTHREAD_MUTEX_lock(&client->mutex);
		assert(client->state ==
		       CONNECTION_MANAGER__CLIENT_STATE__ACTIVATING);

		if (is_drain_success(drain_result)) {
			change_state(client,
				     CONNECTION_MANAGER__CLIENT_STATE__ACTIVE);
		} else {
			change_state(client,
				     CONNECTION_MANAGER__CLIENT_STATE__DRAINED);
		}
		break;
	}
	case CONNECTION_MANAGER__CLIENT_STATE__ACTIVATING: {
		LogDebugConnection(
			connection,
			"Client is activating in another thread, waiting");
		CONN_AUTO_TRACEPOINT(
			connection, activate_clinet__activating, TRACE_INFO,
			"Client is activating in another thread, waiting");
		wait_for_state_change(client);
		break;
	}
	case CONNECTION_MANAGER__CLIENT_STATE__ACTIVE: {
		LogDebugConnection(connection, "Client is already active");
		CONN_AUTO_TRACEPOINT(connection, activate_clinet__active,
				     TRACE_INFO, "Client is already active");
		break;
	}
	case CONNECTION_MANAGER__CLIENT_STATE__DRAINING: {
		LogDebugConnection(connection, "Canceling ongoing drain");
		CONN_AUTO_TRACEPOINT(connection, activate_clinet__draining,
				     TRACE_INFO, "Canceling ongoing drain");
		change_state(client, CONNECTION_MANAGER__CLIENT_STATE__ACTIVE);
		break;
	}
	default: {
		CONN_AUTO_TRACEPOINT(connection, activate_clinet__state_unknown,
				     TRACE_CRIT,
				     "Unexpected connection manager state {}",
				     client->state);
		LogFatalConnection(connection,
				   "Unexpected connection manager state %d",
				   client->state);
	}
	}
}

void connection_manager__connection_init(SVCXPRT *xprt)
{
	LogInfo(COMPONENT_XPRT, "fd %d: Connection init for xprt %p",
		xprt->xp_fd, xprt);
	GSH_AUTO_TRACEPOINT(PROV_NAME, conn_init, TRACE_INFO,
			    "fd {}: Connection init for xprt {}", xprt->xp_fd,
			    xprt);
	connection_manager__connection_t *const connection =
		xprt_to_connection(xprt);
	if (!connection) {
		GSH_AUTO_TRACEPOINT(
			PROV_NAME, conn_init_no_conn, TRACE_CRIT,
			"fd {}: Must call nfs_rpc_alloc_user_data before calling {}",
			xprt->xp_fd, __func__);
		LogFatal(
			COMPONENT_XPRT,
			"fd %d: Must call nfs_rpc_alloc_user_data before calling %s",
			xprt->xp_fd, __func__);
	}
	/* No need to hold XPRT refcount, because the connection struct is
	 * stored in the XPRT custom user data. When the XPRT is destroyed it
	 * calls connection_manager__connection_finished  */
	connection->xprt = xprt;
	connection->is_destroyed = false;
	connection->destroy_start = 0;

	connection->is_managed = false;
	/* connection_init is called when the connection is just established.
	 * However, till the first packet on the connection, which can be a
	 * proxy protocol packet, arrives at the connection, the remote address
	 * is not determined, and therefore calling to svc_getrpccaller should
	 * not be used till then.
	 * When the svc_vc handles the first packet, it knows what is the
	 * remote address and update any upper layer registered for this
	 * notification.    */
	connection->gsh_client = NULL;
}

enum connection_manager__connection_started_t
connection_manager__connection_started(SVCXPRT *xprt)
{
	enum connection_manager__connection_started_t result;
	struct timespec start_time;

	now(&start_time);
	sockaddr_t *const client_address = svc_getrpccaller(xprt);
	struct gsh_client *const gsh_client =
		get_gsh_client(client_address, /*lookup_only=*/false);
	connection_manager__client_t *const client =
		&gsh_client->connection_manager;
	LogDebugClient(client, "fd %d: Connection started", xprt->xp_fd);
	CLIENT_AUTO_TRACEPOINT(client, conn_started, TRACE_INFO,
			       "fd {}: Connection started", xprt->xp_fd);

	connection_manager__connection_t *const connection =
		xprt_to_connection(xprt);
	if (!connection) {
		CLIENT_AUTO_TRACEPOINT(
			client, conn_started_no_conn, TRACE_CRIT,
			"fd {}: Must call nfs_rpc_alloc_user_data before calling {}",
			xprt->xp_fd, TP_STR(__func__));
		LogFatalClient(
			client,
			"fd %d: Must call nfs_rpc_alloc_user_data before calling %s",
			xprt->xp_fd, __func__);
	}

	/* assert that connecton_init function was called before.
	 * The init function should have set the xprt in the connection. */
	if (connection->xprt != xprt) {
		CLIENT_AUTO_TRACEPOINT(
			client, conn_started_xprt, TRACE_CRIT,
			"found connection xprt {} is different from given xprt {}",
			connection->xprt, xprt);
		LogFatalClient(
			client,
			"found connection xprt %p is different from given xprt %p ",
			connection->xprt, xprt);
	}

	/* We need connection->gsh_client set here, we will NULL it back out
	 * if we do not end up managing the client.
	 */
	connection->gsh_client = gsh_client;
	connection->is_destroyed = false;
	connection->destroy_start = 0;

	connection->is_managed = should_manage_connection(client_address);
	if (!connection->is_managed) {
		LogDebugConnection(
			connection,
			"Connection is not managed by connection manager");
		CONN_AUTO_TRACEPOINT(
			connection, conn_started_not_mananged, TRACE_INFO,
			"Connection is not managed by connection manager");
		connection->gsh_client = NULL;
		put_gsh_client(gsh_client);
		result = CONNECTION_MANAGER__CONNECTION_STARTED__ALLOW;
		goto out;
	}

	PTHREAD_MUTEX_lock(&client->mutex);
	try_activate_client_if_needed(connection);

	if (client->state != CONNECTION_MANAGER__CLIENT_STATE__ACTIVE) {
		LogWarnConnection(connection, "Failed with state %d",
				  client->state);
		CONN_AUTO_TRACEPOINT(connection, conn_started_not_active,
				     TRACE_WARNING, "Failed with state {}",
				     client->state);
		connection->is_managed = false;
		PTHREAD_MUTEX_unlock(&client->mutex);
		connection->gsh_client = NULL;
		put_gsh_client(gsh_client);
		result = CONNECTION_MANAGER__CONNECTION_STARTED__DROP;
		goto out;
	}

	LogDebugConnection(connection, "Success (xp_refcnt %d)",
			   xprt->xp_refcnt);
	CONN_AUTO_TRACEPOINT(connection, conn_started_done, TRACE_INFO,
			     "Success (xp_refcnt {})", xprt->xp_refcnt);
	glist_add_tail(&client->connections, &connection->node);
	client->connections_count++;
	PTHREAD_MUTEX_unlock(&client->mutex);
	result = CONNECTION_MANAGER__CONNECTION_STARTED__ALLOW;

out:
	connection_manager_metrics__connection_started_done(result,
							    &start_time);
	return result;
}

void connection_manager__connection_finished(const SVCXPRT *xprt)
{
	connection_manager__connection_t *const connection =
		xprt_to_connection(xprt);
	if (!connection || !connection->is_managed) {
		LogInfo(COMPONENT_XPRT, "fd %d: Connection is not managed",
			xprt->xp_fd);
		GSH_AUTO_TRACEPOINT(PROV_NAME, conn_fini_no_conn, TRACE_INFO,
				    "fd {}: Connection is not managed",
				    xprt->xp_fd);
		return;
	}
	struct gsh_client *const gsh_client = connection->gsh_client;
	connection_manager__client_t *const client =
		&gsh_client->connection_manager;
	LogDebugConnection(connection, "Connection finished");
	CONN_AUTO_TRACEPOINT(connection, conn_finished, TRACE_INFO,
			     "Connection finished");

	PTHREAD_MUTEX_lock(&client->mutex);
	glist_del(&connection->node);
	assert(client->connections_count > 0);
	client->connections_count--;
	if (client->connections_count == 0)
		PTHREAD_COND_broadcast(&client->cond_change);
	PTHREAD_MUTEX_unlock(&client->mutex);

	connection->xprt = NULL;
	connection->gsh_client = NULL;
	put_gsh_client(gsh_client);
}

void connection_manager__init(void)
{
	connection_manager_metrics__init();
}

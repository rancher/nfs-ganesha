# SPDX-License-Identifier: LGPL-3.0-or-later
#-------------------------------------------------------------------------------
#
# Copyright Panasas, 2012
# Contributor: Jim Lieb <jlieb@panasas.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#-------------------------------------------------------------------------------
include_directories(
  ${DBUS_INCLUDE_DIRS}
)

########### next target ###############

SET(gshdbus_STAT_SRCS
   dbus_server.c
   properties_handler.c
   signal_handler.c
   dbus_heartbeat.c
)

add_library(gshdbus OBJECT ${gshdbus_STAT_SRCS})
add_sanitizers(gshdbus)
set_target_properties(gshdbus PROPERTIES COMPILE_FLAGS "-fPIC")

if (USE_LTTNG)
add_dependencies(gshdbus gsh_trace_header_generate)
include("${CMAKE_BINARY_DIR}/gsh_lttng_generation_file_properties.cmake")
endif (USE_LTTNG)

########### install files ###############

/*
 *  ECDH context structures (private header for internal use only)
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_PRIVATE_ECDH_H
#define MBEDTLS_PRIVATE_ECDH_H

#include "mbedtls/private/ecp.h"

#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
#include "tf-psa-crypto/private/everest/everest.h"
#endif

typedef enum {
    MBEDTLS_ECDH_VARIANT_NONE = 0,
    MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0,
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
    MBEDTLS_ECDH_VARIANT_EVEREST,
#endif
} mbedtls_ecdh_variant;

typedef enum {
    MBEDTLS_ECDH_OURS,
    MBEDTLS_ECDH_THEIRS,
} mbedtls_ecdh_side;

typedef struct mbedtls_ecdh_context_mbed {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point Qp;
    mbedtls_mpi z;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx rs;
#endif
} mbedtls_ecdh_context_mbed;

typedef struct mbedtls_ecdh_context {
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point Qp;
    mbedtls_mpi z;
    int point_format;
    mbedtls_ecp_point Vi;
    mbedtls_ecp_point Vf;
    mbedtls_mpi _d;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    int restart_enabled;
    mbedtls_ecp_restart_ctx rs;
#endif
#else
    uint8_t point_format;
    mbedtls_ecp_group_id grp_id;
    mbedtls_ecdh_variant var;
    union {
        mbedtls_ecdh_context_mbed mbed_ecdh;
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        mbedtls_everest_context everest_ecdh;
#endif
    } ctx;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    uint8_t restart_enabled;
    mbedtls_ecp_restart_ctx rs;
#endif
#endif /* MBEDTLS_ECDH_LEGACY_CONTEXT */
} mbedtls_ecdh_context;

#endif /* MBEDTLS_PRIVATE_ECDH_H */

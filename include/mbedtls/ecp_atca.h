/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MBEDTLS_ECP_ATCA_H
#define MBEDTLS_ECP_ATCA_H

#if defined(MBEDTLS_ECP_ATCA)

#include "mbedtls/bignum.h"
#include "mbedtls/pk_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ECP_ATCA_SLOT_INVALID 0xff
#define MBEDTLS_ECP_ATCA_SLOT_TEMPKEY 0x10

#define MBEDTLS_ECP_ATCA_KEY_FILE_NAME_PREFIX "ATCA:"

#define MBEDTLS_ECP_ATCA_KEY_NAME "EC(ATCA)"
extern const mbedtls_pk_info_t mbedtls_eckey_atca_info;

int ecdsa_atca_verify(mbedtls_ecdsa_context *ctx,
                      const unsigned char *hash, size_t hlen,
                      const mbedtls_mpi *r, const mbedtls_mpi *s);

int ecp_atca_ecdh_gen_keypair(mbedtls_ecp_point *Q, uint8_t *slot,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
int ecp_atca_ecdh_compute_pms(uint8_t slot, mbedtls_ecp_point *Qp, mbedtls_mpi *z);

/* Try to claim tempkey for ECDH, if not currently claimed.
 * Returns true if claimed.
 * If claimed, must be released later. */
int ecp_atca_try_claim_tempkey(void);
void ecp_atca_release_tempkey(void);

/* Provided externally, returns 1 if the chip is available (via basic API). */
extern int mbedtls_atca_is_available(void);

/* Provided externally and returns a bitmask of slots available for ECDH:
 * bit #N = 1 -> slot N available for ECDH. Only slots 0-7 can be used for
 * ECC key operations, so 8 bits is enough. */
extern uint16_t mbedtls_atca_get_ecdh_slots_mask(void);

/* Provided externally, returns true if chip is ATECC608A. */
extern int mbedtls_atca_is_608(void);

#ifdef __cplusplus
}
#endif

#endif /* defined(MBEDTLS_ECP_ATCA) */

#endif /* ecp_atca.h */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// FIXME: some of these class types have items in them with arenas, but we can't hold a reference
//        to an arena, so check to make sure we copy the items out and don't store the
//        the item with the arena in it.

#ifndef NSS_NSS_MODULE_H
#define NSS_NSS_MODULE_H

#define NSS_NSS_MODULE_NAME "nss"

/* NSPR header files */
#undef HAVE_LONG_LONG           /* FIXME: both Python.h and nspr.h define HAVE_LONG_LONG  */
#include <stdbool.h>
#include "nspr.h"
#include "cert.h"
#include "nss.h"
#include "ssl.h"
#include "sslt.h"
#include "key.h"
#include "pk11pub.h"
#include "pkcs12.h"

/* ========================================================================== */

/* ========================================================================== */
/* =============================== SecItem Class ============================ */
/* ========================================================================== */

typedef enum SECItemKindEnum {
    SECITEM_unknown,
    SECITEM_buffer,
    SECITEM_dist_name,
    SECITEM_session_id,
    SECITEM_signed_data,
    SECITEM_signature,
    SECITEM_algorithm,
    SECITEM_iv_param,
    SECITEM_wrapped_key,
    SECITEM_cert_extension_oid,
    SECITEM_cert_extension_value,
    SECITEM_oid,
    SECITEM_utf8_string,
    SECITEM_bit_string,
    SECITEM_certificate,
    SECITEM_sym_key_params,
} SECItemKind;

typedef struct {
    PyObject_HEAD
    SECItem item;
    SECItemKind kind;
} SecItem;

#define SecItem_GET_SIZE(op)  (Py_ssize_t)(op->item.len)

/* ========================================================================== */
/* =============================== PK11Slot Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PK11SlotInfo *slot;
} PK11Slot;

/* ========================================================================== */
/* ================================ CertDB Class ============================ */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    CERTCertDBHandle *handle;
} CertDB;


/* ========================================================================== */
/* ======================== CertificateExtension Class ====================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SecItem *py_oid;
    SecItem *py_value;
    int critical;
} CertificateExtension;

/* ========================================================================== */
/* ============================ Certificate Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    CERTCertificate *cert;
} Certificate;


/* ========================================================================== */
/* ============================= PrivateKey Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SECKEYPrivateKey *private_key;
} PrivateKey;

/* ========================================================================== */
/* ============================== SignedCRL Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    CERTSignedCrl *signed_crl;
} SignedCRL;

/* ========================================================================== */
/* ============================ RSAPublicKey Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PyObject *py_modulus;
    PyObject *py_exponent;
} RSAPublicKey;

/* ========================================================================== */
/* ============================ DSAPublicKey Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PyObject *py_pqg_params;
    PyObject *py_public_value;
} DSAPublicKey;

/* ========================================================================== */
/* ============================ RSAGenParams Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PK11RSAGenParams params;
} RSAGenParams;

/* ========================================================================== */
/* ============================ KEYPQGParams Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SECKEYPQGParams params;
} KEYPQGParams;

/* ========================================================================== */
/* ============================ AlgorithmID Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SECAlgorithmID id;
    PyObject *py_id;
    PyObject *py_parameters;
} AlgorithmID;

/* ========================================================================== */
/* ============================= SignedData Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTSignedData signed_data;
    PyObject *py_der;
    PyObject *py_data;
    PyObject *py_algorithm;
    PyObject *py_signature;
} SignedData;

/* ========================================================================== */
/* ============================= PublicKey Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SECKEYPublicKey *pk;
    PyObject *py_rsa_key;
    PyObject *py_dsa_key;
} PublicKey;

/* ========================================================================== */
/* ======================== SubjectPublicKeyInfo Class ====================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    PyObject *py_algorithm;
    PyObject *py_public_key;
} SubjectPublicKeyInfo;

/* ========================================================================== */
/* ============================= PK11SymKey Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PK11SymKey *pk11_sym_key;
} PyPK11SymKey;

/* ========================================================================== */
/* ============================= PK11Context Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PK11Context *pk11_context;
} PyPK11Context;

/* ========================================================================== */
/* ================================= AVA Class ============================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTAVA *ava;
} AVA;

/* ========================================================================== */
/* ================================= RDN Class ============================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTRDN *rdn;
} RDN;

/* ========================================================================== */
/* ================================= DN Class =============================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTName name;
} DN;

/* ========================================================================== */
/* ============================= GeneralName Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTGeneralName *name;
} GeneralName;

/* ========================================================================== */
/* =========================== CRLDistributionPt Class ====================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CRLDistributionPoint *pt;
} CRLDistributionPt;

/* ========================================================================== */
/* ========================== CRLDistributionPts Class ====================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PyObject *py_pts;
} CRLDistributionPts;

/* ========================================================================== */
/* ========================== AuthorityInfoAccess Class ===================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTAuthInfoAccess *aia;
} AuthorityInfoAccess;

/* ========================================================================== */
/* ========================= AuthorityInfoAccesses Class ==================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PyObject *py_aias;
} AuthorityInfoAccesses;

/* ========================================================================== */
/* ============================== AuthKeyID Class =========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTAuthKeyID *auth_key_id;
} AuthKeyID;

/* ========================================================================== */
/* ========================== BasicConstraints Class ======================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    CERTBasicConstraints bc;
} BasicConstraints;

/* ========================================================================== */
/* ============================= CertAttribute Class ======================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTAttribute attr;
    SECOidTag oid_tag;
    Py_ssize_t n_values;
    CERTCertExtension **extensions;   /* null terminated array of SECItems */
} CertAttribute;

/* ========================================================================== */
/* ========================= CertificateRequest Class ======================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTSignedData signed_data;
    CERTCertificateRequest *cert_req;
    CERTCertExtension **extensions;   /* null terminated array of SECItems */
} CertificateRequest;

/* ========================================================================== */
/* =========================== InitParameters Class ========================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    NSSInitParameters params;
} InitParameters;

/* ========================================================================== */
/* ============================= InitContext Class ========================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    NSSInitContext *context;
} InitContext;

/* ========================================================================== */
/* =========================== PKCS12DecodeItem Class ======================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SECOidTag type;
    PRBool    has_key;
    PyObject *py_signed_cert_der;
    PyObject *py_cert;
    PyObject *py_friendly_name;
    PyObject *py_shroud_algorithm_id;
} PKCS12DecodeItem;

/* ========================================================================== */
/* ============================ PKCS12Decoder Class ========================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SECItem *ucs2_password_item;
    SEC_PKCS12DecoderContext *decoder_ctx;
    PyObject *py_decode_items;    /* tuple */
} PKCS12Decoder;

/* ========================================================================== */
/* ========================== CertVerifyLogNode Class ======================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    CERTVerifyLogNode node;
} CertVerifyLogNode;

/* ========================================================================== */
/* ============================ CertVerifyLog Class ========================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    CERTVerifyLog log;
} CertVerifyLog;

/* ========================================================================== */

typedef struct {
    PyTypeObject *pk11slot_type;
    PyTypeObject *certdb_type;
    PyTypeObject *certificate_type;
    PyTypeObject *private_key_type;
    PyTypeObject *sec_item_type;
    PyObject *(*Certificate_new_from_CERTCertificate)(CERTCertificate *cert, bool add_reference);
    PyObject *(*PrivateKey_new_from_SECKEYPrivateKey)(SECKEYPrivateKey *private_key);
    PyObject *(*SecItem_new_from_SECItem)(const SECItem *item, SECItemKind type);
    PyObject *(*cert_distnames_new_from_CERTDistNames)(CERTDistNames *names);
    CERTDistNames *(*cert_distnames_as_CERTDistNames)(PyObject *py_distnames);
    int (*_AddIntConstantWithLookup)(PyObject *module,
                                     const char *name, long value,
                                     const char *prefix,
                                     PyObject *name_to_value,
                                     PyObject *value_to_name);
    int (*_AddIntConstantAlias)(const char *name, long value,
                                PyObject *name_to_value);
    PyObject *(*format_from_lines)(format_lines_func formatter, PyObject *self,
                                   PyObject *args, PyObject *kwds);
    PyObject *(*line_fmt_tuple)(int level, const char *label,
                                PyObject *py_value);
    PyObject *(*obj_sprintf)(const char *fmt, ...);
    PyObject *(*obj_to_hex)(PyObject *obj,
                            int octets_per_line, char *separator);
    PyObject *(*raw_data_to_hex)(unsigned char *data, int data_len,
                                 int octets_per_line, char *separator);
    PyObject *(*fmt_label)(int level, char *label);
    PyObject *(*timestamp_to_DateTime)(time_t timestamp, bool utc);



} PyNSPR_NSS_C_API_Type;

#ifdef NSS_NSS_MODULE

#define PyPK11Slot_Check(op) PyObject_TypeCheck(op, &PK11SlotType)
#define PyCertDB_Check(op) PyObject_TypeCheck(op, &CertDBType)
#define PyCertificate_Check(op) PyObject_TypeCheck(op, &CertificateType)
#define PyPrivateKey_Check(op) PyObject_TypeCheck(op, &PrivateKeyType)
#define PySecItem_Check(op) PyObject_TypeCheck(op, &SecItemType)
#define PySymKey_Check(op) PyObject_TypeCheck(op, &PK11SymKeyType)

PyObject *
PK11Slot_new_from_PK11SlotInfo(PK11SlotInfo *slot);

#else  /* not NSS_NSS_MODULE */

#define CertDBType (*nspr_nss_c_api.certdb_type)
#define CertificateType (*nspr_nss_c_api.certificate_type)
#define PrivateKeyType (*nspr_nss_c_api.private_key_type)
#define SecItemType (*nspr_nss_c_api.sec_item_type)

#define PyPK11Slot_Check(op) PyObject_TypeCheck(op, nspr_nss_c_api.pk11slot_type)
#define PyCertDB_Check(op) PyObject_TypeCheck(op, nspr_nss_c_api.certdb_type)
#define PyCertificate_Check(op) PyObject_TypeCheck(op, nspr_nss_c_api.certificate_type)
#define PyPrivateKey_Check(op) PyObject_TypeCheck(op, nspr_nss_c_api.private_key_type)
#define PySecItem_Check(op) PyObject_TypeCheck(op, nspr_nss_c_api.sec_item_type)

static PyNSPR_NSS_C_API_Type nspr_nss_c_api;

#define Certificate_new_from_CERTCertificate (*nspr_nss_c_api.Certificate_new_from_CERTCertificate)
#define PrivateKey_new_from_SECKEYPrivateKey (*nspr_nss_c_api.PrivateKey_new_from_SECKEYPrivateKey)
#define SecItem_new_from_SECItem (*nspr_nss_c_api.SecItem_new_from_SECItem)
#define cert_distnames_new_from_CERTDistNames (*nspr_nss_c_api.cert_distnames_new_from_CERTDistNames)
#define cert_distnames_as_CERTDistNames (*nspr_nss_c_api.cert_distnames_as_CERTDistNames)
#define _AddIntConstantWithLookup (*nspr_nss_c_api._AddIntConstantWithLookup)
#define _AddIntConstantAlias (*nspr_nss_c_api._AddIntConstantAlias)
#define format_from_lines (*nspr_nss_c_api.format_from_lines)
#define line_fmt_tuple (*nspr_nss_c_api.line_fmt_tuple)
#define obj_sprintf (*nspr_nss_c_api.obj_sprintf)
#define obj_to_hex (*nspr_nss_c_api.obj_to_hex)
#define raw_data_to_hex (*nspr_nss_c_api.raw_data_to_hex)
#define fmt_label (*nspr_nss_c_api.fmt_label)
#define timestamp_to_DateTime (*nspr_nss_c_api.timestamp_to_DateTime)

static int
import_nspr_nss_c_api(void)
{
    void *api = NULL;

    if ((api = PyCapsule_Import(PACKAGE_NAME "." NSS_NSS_MODULE_NAME "._C_API", 0)) == NULL) {
        return -1;
    }

    memcpy(&nspr_nss_c_api, api, sizeof(nspr_nss_c_api));

    return 0;
}

#endif /* NSS_NSS_MODULE */
#endif /* NSS_NSS_MODULE_H */

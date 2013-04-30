/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// FIXME: some of these class types have items in them with arenas, but we can't hold a reference
//        to an arena, so check to make sure we copy the items out and don't store the
//        the item with the arena in it.

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

typedef enum RepresentationKindEnum {
    AsObject,
    AsString,
    AsTypeString,
    AsTypeEnum,
    AsLabeledString,
    AsEnum,
    AsEnumName,
    AsEnumDescription,
    AsIndex,
    AsDottedDecimal,
} RepresentationKind;


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
/* ========================= CertificateRequest Class ======================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRArenaPool *arena;
    CERTSignedData signed_data;
    CERTCertificateRequest *cert_req;
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

static int
import_nspr_nss_c_api(void)
{
    PyObject *module = NULL;
    PyObject *c_api_object = NULL;
    void *api = NULL;

    if ((module = PyImport_ImportModule("nss.nss")) == NULL)
        return -1;

    if ((c_api_object = PyObject_GetAttrString(module, "_C_API")) == NULL) {
        Py_DECREF(module);
        return -1;
    }

    if (!(PyCObject_Check(c_api_object))) {
        Py_DECREF(c_api_object);
        Py_DECREF(module);
        return -1;
    }

    if ((api = PyCObject_AsVoidPtr(c_api_object)) == NULL) {
        Py_DECREF(c_api_object);
        Py_DECREF(module);
        return -1;
    }

    memcpy(&nspr_nss_c_api, api, sizeof(nspr_nss_c_api));
    Py_DECREF(c_api_object);
    Py_DECREF(module);
    return 0;
}

#endif /* NSS_NSS_MODULE */

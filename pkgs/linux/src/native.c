#define _DEFAULT_SOURCE
#define GCR_API_SUBJECT_TO_CHANGE
#include <gcr/gcr.h>
#include <libsecret/secret.h>
#include <fido.h>
#include <fido/es256.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <string.h>
#include <stdlib.h>

/* All exported calls are serialized by the Rust adapter. No secret is logged. */
static const SecretSchema schema = {
    "fyi.seccy.vault", SECRET_SCHEMA_NONE,
    {{"vault", SECRET_SCHEMA_ATTRIBUTE_STRING}, {"key", SECRET_SCHEMA_ATTRIBUTE_STRING}, {NULL, 0}},
    0, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

void sc_free(char *value) { if (value) { explicit_bzero(value, strlen(value)); g_free(value); } }

int sc_secret(const char *vault, const char *key, const char *value, int operation, char **out) {
    GError *error = NULL;
    gboolean ok = TRUE;
    if (operation == 0) {
        char *result = secret_password_lookup_sync(&schema, NULL, &error, "vault", vault, "key", key, NULL);
        *out = result ? g_strdup(result) : NULL;
        if (result) secret_password_free(result);
    } else if (operation == 1) {
        ok = secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT, "Seccy encrypted TPM key",
            value, NULL, &error, "vault", vault, "key", key, NULL);
    } else {
        secret_password_clear_sync(&schema, NULL, &error, "vault", vault, "key", key, NULL);
    }
    if (error) { g_error_free(error); return -1; }
    return ok ? 0 : -1;
}

int sc_devices(char **out) {
    fido_init(0);
    fido_dev_info_t *list = fido_dev_info_new(64);
    size_t count = 0;
    int result = fido_dev_info_manifest(list, 64, &count);
    GString *text = g_string_new("");
    if (result == FIDO_OK) {
        for (size_t i = 0; i < count; i++) {
            const fido_dev_info_t *device = fido_dev_info_ptr(list, i);
            const char *path = fido_dev_info_path(device);
            if (path && !strchr(path, '\n')) g_string_append_printf(text, "%s\n", path);
        }
    }
    fido_dev_info_free(&list, 64);
    *out = g_string_free(text, FALSE);
    return result;
}

static char *pin_prompt(const char *details) {
    GError *error = NULL;
    GcrPrompt *prompt = gcr_system_prompt_open(30, NULL, &error);
    if (error) g_error_free(error);
    if (!prompt) return NULL;
    gcr_prompt_set_message(prompt, "Seccy: enter your security key PIN");
    gcr_prompt_set_description(prompt, details);
    const char *pin = gcr_prompt_password_run(prompt, NULL, &error);
    char *copy = pin ? g_strdup(pin) : NULL;
    if (error) g_error_free(error);
    gcr_prompt_close(prompt);
    g_object_unref(prompt);
    return copy;
}

typedef struct {
    fido_dev_t *device;
    fido_cred_t *credential;
    fido_assert_t *assertion;
    const char *pin;
    gint done;
    int result;
    gboolean cancelled;
    gboolean replied;
} FidoWork;

static gpointer fido_worker(gpointer data) {
    FidoWork *work = data;
    work->result = work->credential ? fido_dev_make_cred(work->device, work->credential, work->pin)
                                    : fido_dev_get_assert(work->device, work->assertion, work->pin);
    g_atomic_int_set(&work->done, 1);
    return NULL;
}

static void confirmed(GObject *object, GAsyncResult *result, gpointer data) {
    FidoWork *work = data;
    GError *error = NULL;
    GcrPromptReply reply = gcr_prompt_confirm_finish(GCR_PROMPT(object), result, &error);
    if (error) g_error_free(error);
    if (reply != GCR_PROMPT_REPLY_CONTINUE) {
        work->cancelled = TRUE;
        if (!g_atomic_int_get(&work->done)) fido_dev_cancel(work->device);
    }
    work->replied = TRUE;
}

static int perform(FidoWork *work, const char *details) {
    GError *error = NULL;
    GcrPrompt *prompt = gcr_system_prompt_open(30, NULL, &error);
    if (error) g_error_free(error);
    if (!prompt) return -1;
    gcr_prompt_set_message(prompt, "Seccy: verify with your security key");
    gcr_prompt_set_description(prompt, details);
    gcr_prompt_set_continue_label(prompt, "Waiting for security key");
    gcr_prompt_confirm_async(prompt, NULL, confirmed, work);
    GThread *thread = g_thread_new("seccy-fido", fido_worker, work);
    while (!g_atomic_int_get(&work->done)) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_usleep(10000);
    }
    g_thread_join(thread);
    /* Closing a successful prompt also completes the pending confirmation. */
    gboolean cancelled = work->cancelled;
    gcr_prompt_close(prompt);
    while (!work->replied) g_main_context_iteration(NULL, TRUE);
    g_object_unref(prompt);
    return cancelled ? -1 : work->result;
}

/* Credential public keys are libfido2's 64-byte ES256 x/y representation. */
int sc_fido(const char *device_path, const char *rp, const unsigned char *user,
    const unsigned char *challenge, const unsigned char *salt, const unsigned char *id, size_t id_len,
    const unsigned char *public_key, const char *details,
    unsigned char *new_id, size_t *new_id_len, unsigned char *new_public, unsigned char *secret) {
    fido_init(0);
    fido_dev_t *device = fido_dev_new();
    fido_cred_t *credential = NULL;
    fido_assert_t *assertion = NULL;
    es256_pk_t *pk = NULL;
    char *pin = NULL;
    int result = -1;
    if (!device || fido_dev_open(device, device_path) != FIDO_OK) goto done;
    fido_dev_set_timeout(device, 30000);
    if (!fido_dev_is_fido2(device)) goto done;
    gboolean biometric = fido_dev_has_uv(device) && fido_dev_supports_uv(device);
    if (!biometric) {
        if (!fido_dev_has_pin(device)) goto done;
        pin = pin_prompt(details);
        if (!pin || !*pin) goto done;
    }
    if (!id) {
        credential = fido_cred_new();
        if (!credential || fido_cred_set_type(credential, COSE_ES256) != FIDO_OK ||
            fido_cred_set_rp(credential, rp, "Seccy") != FIDO_OK ||
            fido_cred_set_user(credential, user, 32, "seccy", "Seccy vault", NULL) != FIDO_OK ||
            fido_cred_set_clientdata_hash(credential, challenge, 32) != FIDO_OK ||
            fido_cred_set_extensions(credential, FIDO_EXT_HMAC_SECRET) != FIDO_OK ||
            fido_cred_set_prot(credential, FIDO_CRED_PROT_UV_REQUIRED) != FIDO_OK ||
            fido_cred_set_uv(credential, biometric ? FIDO_OPT_TRUE : FIDO_OPT_OMIT) != FIDO_OK) goto done;
        FidoWork work = {.device = device, .credential = credential, .pin = pin};
        int status = perform(&work, details);
        if (biometric && (status == FIDO_ERR_UV_BLOCKED || status == FIDO_ERR_UV_INVALID || status == FIDO_ERR_PIN_REQUIRED) && fido_dev_has_pin(device)) {
            pin = pin_prompt(details);
            if (!pin || !*pin) goto done;
            biometric = FALSE;
            fido_cred_set_uv(credential, FIDO_OPT_OMIT);
            FidoWork retry = {.device = device, .credential = credential, .pin = pin};
            status = perform(&retry, details);
        }
        if (status != FIDO_OK) goto done;
        int verified = fido_cred_x5c_ptr(credential) ? fido_cred_verify(credential) : fido_cred_verify_self(credential);
        if (verified != FIDO_OK || fido_cred_prot(credential) != FIDO_CRED_PROT_UV_REQUIRED ||
            fido_cred_pubkey_len(credential) != 64 || fido_cred_id_len(credential) > *new_id_len) goto done;
        *new_id_len = fido_cred_id_len(credential);
        memcpy(new_id, fido_cred_id_ptr(credential), *new_id_len);
        memcpy(new_public, fido_cred_pubkey_ptr(credential), 64);
        id = new_id; id_len = *new_id_len; public_key = new_public;
    }
    assertion = fido_assert_new();
    pk = es256_pk_new();
    if (!assertion || !pk || es256_pk_from_ptr(pk, public_key, 64) != FIDO_OK ||
        fido_assert_set_rp(assertion, rp) != FIDO_OK ||
        fido_assert_allow_cred(assertion, id, id_len) != FIDO_OK ||
        fido_assert_set_clientdata_hash(assertion, challenge, 32) != FIDO_OK ||
        fido_assert_set_extensions(assertion, FIDO_EXT_HMAC_SECRET) != FIDO_OK ||
        fido_assert_set_hmac_salt(assertion, salt, 32) != FIDO_OK ||
        fido_assert_set_up(assertion, FIDO_OPT_TRUE) != FIDO_OK ||
        fido_assert_set_uv(assertion, biometric ? FIDO_OPT_TRUE : FIDO_OPT_OMIT) != FIDO_OK) goto done;
    FidoWork work = {.device = device, .assertion = assertion, .pin = pin};
    int status = perform(&work, details);
    if (biometric && (status == FIDO_ERR_UV_BLOCKED || status == FIDO_ERR_UV_INVALID || status == FIDO_ERR_PIN_REQUIRED) && fido_dev_has_pin(device)) {
        pin = pin_prompt(details);
        if (!pin || !*pin) goto done;
        fido_assert_set_uv(assertion, FIDO_OPT_OMIT);
        FidoWork retry = {.device = device, .assertion = assertion, .pin = pin};
        status = perform(&retry, details);
    }
    if (status != FIDO_OK || fido_assert_count(assertion) != 1 ||
        (fido_assert_flags(assertion, 0) & 5) != 5 || fido_assert_hmac_secret_len(assertion, 0) != 32 ||
        fido_assert_verify(assertion, 0, COSE_ES256, pk) != FIDO_OK) goto done;
    memcpy(secret, fido_assert_hmac_secret_ptr(assertion, 0), 32);
    result = 0;
done:
    sc_free(pin);
    es256_pk_free(&pk);
    fido_assert_free(&assertion);
    fido_cred_free(&credential);
    if (device) { fido_dev_close(device); fido_dev_free(&device); }
    return result;
}

/* Serialized TPM blobs contain TPM2B_PUBLIC followed by TPM2B_PRIVATE. */
static int tpm_operation(const char *transport, int operation, const unsigned char *auth, unsigned char *blob, size_t *blob_len,
    const unsigned char *input, unsigned char *output, unsigned char *parent_name) {
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *ctx = NULL;
    ESYS_TR parent = ESYS_TR_NONE, key = ESYS_TR_NONE, session = ESYS_TR_NONE;
    TPM2B_PUBLIC *public = NULL;
    TPM2B_PRIVATE *private = NULL;
    TPM2B_NAME *name = NULL;
    TPMT_SIGNATURE *signature = NULL;
    TPM2B_ECC_POINT *point = NULL;
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_AUTH authorization = {0};
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcr = {0};
    TPM2B_PUBLIC template = {.publicArea = {
        .type = TPM2_ALG_ECC, .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT,
        .parameters.eccDetail = {.symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
            .scheme.scheme = TPM2_ALG_NULL, .curveID = TPM2_ECC_NIST_P256, .kdf.scheme = TPM2_ALG_NULL}
    }};
    int result = -1;
#define CHECK(call) do { if ((call) != TSS2_RC_SUCCESS) goto done; } while (0)
    CHECK(Tss2_TctiLdr_Initialize(transport, &tcti));
    CHECK(Esys_Initialize(&ctx, tcti, NULL));
    CHECK(Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &sensitive, &template, &outside, &pcr, &parent, &public, NULL, NULL, NULL));
    Esys_Free(public); public = NULL;
    CHECK(Esys_TR_GetName(ctx, parent, &name));
    if (name->size != 34) goto done;
    memcpy(parent_name, name->name, 34);
    if (operation == 0) { result = 0; goto done; }
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB};
    CHECK(Esys_StartAuthSession(ctx, parent, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        NULL, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256, &session));
    if (operation == 1) {
        CHECK(Esys_TRSess_SetAttributes(ctx, session, TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT, 0xff));
        sensitive.sensitive.userAuth.size = 32;
        memcpy(sensitive.sensitive.userAuth.buffer, auth, 32);
        template.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA;
        template.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        CHECK(Esys_Create(ctx, parent, session, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template,
            &outside, &pcr, &private, &public, NULL, NULL, NULL));
        size_t offset = 0;
        CHECK(Tss2_MU_TPM2B_PUBLIC_Marshal(public, blob, *blob_len, &offset));
        CHECK(Tss2_MU_TPM2B_PRIVATE_Marshal(private, blob, *blob_len, &offset));
        *blob_len = offset;
        TPM2B_ECC_PARAMETER *x = &public->publicArea.unique.ecc.x, *y = &public->publicArea.unique.ecc.y;
        if (x->size > 32 || y->size > 32) goto done;
        memset(output, 0, 65); output[0] = 4;
        memcpy(output + 33 - x->size, x->buffer, x->size);
        memcpy(output + 65 - y->size, y->buffer, y->size);
    } else {
        TPM2B_PUBLIC pub = {0}; TPM2B_PRIVATE priv = {0}; size_t offset = 0;
        CHECK(Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, *blob_len, &offset, &pub));
        CHECK(Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob, *blob_len, &offset, &priv));
        if (offset != *blob_len) goto done;
        CHECK(Esys_Load(ctx, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &priv, &pub, &key));
        authorization.size = 32; memcpy(authorization.buffer, auth, 32);
        CHECK(Esys_TR_SetAuth(ctx, key, &authorization));
        explicit_bzero(&authorization, sizeof authorization);
        CHECK(Esys_TRSess_SetAttributes(ctx, session, TPMA_SESSION_CONTINUESESSION, 0xff));
        if (operation == 2) {
            TPM2B_DIGEST digest = {.size = 32}; memcpy(digest.buffer, input, 32);
            TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_ECDSA, .details.ecdsa.hashAlg = TPM2_ALG_SHA256};
            TPMT_TK_HASHCHECK validation = {.tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL};
            CHECK(Esys_Sign(ctx, key, session, ESYS_TR_NONE, ESYS_TR_NONE, &digest, &scheme, &validation, &signature));
            TPM2B_ECC_PARAMETER *r = &signature->signature.ecdsa.signatureR, *s = &signature->signature.ecdsa.signatureS;
            if (r->size > 32 || s->size > 32) goto done;
            memset(output, 0, 64);
            memcpy(output + 32 - r->size, r->buffer, r->size); memcpy(output + 64 - s->size, s->buffer, s->size);
        } else if (operation == 3) {
            TPM2B_ECC_POINT peer = {.point = {.x.size = 32, .y.size = 32}};
            memcpy(peer.point.x.buffer, input + 1, 32); memcpy(peer.point.y.buffer, input + 33, 32);
            CHECK(Esys_TRSess_SetAttributes(ctx, session, TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT, 0xff));
            CHECK(Esys_ECDH_ZGen(ctx, key, session, ESYS_TR_NONE, ESYS_TR_NONE, &peer, &point));
            if (point->point.x.size > 32) goto done;
            memset(output, 0, 32); memcpy(output + 32 - point->point.x.size, point->point.x.buffer, point->point.x.size);
        } else goto done;
    }
    result = 0;
done:
    explicit_bzero(&sensitive, sizeof sensitive);
    explicit_bzero(&authorization, sizeof authorization);
    if (point) { explicit_bzero(point, sizeof *point); Esys_Free(point); }
    Esys_Free(public); Esys_Free(private); Esys_Free(name); Esys_Free(signature);
    if (ctx) {
        if (key != ESYS_TR_NONE) Esys_FlushContext(ctx, key);
        if (session != ESYS_TR_NONE) Esys_FlushContext(ctx, session);
        if (parent != ESYS_TR_NONE) Esys_FlushContext(ctx, parent);
        Esys_Finalize(&ctx);
    }
    Tss2_TctiLdr_Finalize(&tcti);
    return result;
}

int sc_tpm(int operation, const unsigned char *auth, unsigned char *blob, size_t *blob_len,
    const unsigned char *input, unsigned char *output, unsigned char *parent_name) {
    /* Never honor environment-provided TCTI overrides in the production backend. */
    return tpm_operation("device:/dev/tpmrm0", operation, auth, blob, blob_len, input, output, parent_name);
}

/* Only the cfg(test) Rust adapter references this entry point. */
int sc_tpm_test(const char *transport, int operation, const unsigned char *auth, unsigned char *blob, size_t *blob_len,
    const unsigned char *input, unsigned char *output, unsigned char *parent_name) {
    return tpm_operation(transport, operation, auth, blob, blob_len, input, output, parent_name);
}

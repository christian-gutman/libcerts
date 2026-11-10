#ifndef CORE_CERTS_H
#define CORE_CERTS_H

#include "core.h"
#include "core_io.h"
#include "core_encoding.h"
#include "core_string.h"
#include "core_crypto.h"

#ifdef __cplusplus
extern "C"
{
#endif
 
    // Obtiene la fecha de vencimiento de un certificado (PFX, PEM o DER).
    // 'outputDate' debe medir al menos 64 bytes. Retorna 1 si tuvo éxito, 0 si falló.
    CORE_API int Cert_GetExpiry(const char *pPath, int pathLen, const char *pPwd, int pwdLen, char *outputDate, size_t maxDateLen);

    // Firma un mensaje y lo codifica en Base64.
    // Retorna un puntero al string Base64 (debe liberarse con free()) o NULL si falla.
    CORE_API char *Cert_SignMessage(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen);

#ifdef __cplusplus
}
#endif

#endif // CORE_CERTS_H

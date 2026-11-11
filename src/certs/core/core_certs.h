/**
 * @file core_certs.h
 * @brief API Core para la gestión y firma digital mediante certificados criptográficos.
 */

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

    /**
     * @brief Obtiene la fecha de vencimiento de un certificado (PFX, PEM o DER).
     *
     * Esta función lee un certificado desde el disco y extrae su fecha de expiración,
     * escribiéndola en formato de texto legible dentro del buffer provisto.
     *
     * @param[in]  pPath       Ruta absoluta o relativa al archivo del certificado.
     * @param[in]  pathLen     Longitud en caracteres de la cadena de texto \p pPath.
     * @param[in]  pPwd        Contraseña del certificado (requerido para PFX, puede ser NULL si no aplica).
     * @param[in]  pwdLen      Longitud en caracteres de la cadena \p pPwd.
     * @param[out] outputDate  Buffer de destino donde se escribirá la fecha. **Debe medir al menos 64 bytes**.
     * @param[in]  maxDateLen  Capacidad total máxima en bytes asignada a \p outputDate.
     *
     * @retval 1 Si la fecha se extrajo y copió con éxito.
     * @retval 0 Si ocurrió un fallo al abrir el archivo, contraseña incorrecta o buffer insuficiente.
     *
     * @note El formato de la cadena resultante en \p outputDate dependerá de la codificación interna del certificado.
     */
    CORE_API int Cert_GetExpiry(const char *pPath, int pathLen, const char *pPwd, int pwdLen, char *outputDate, size_t maxDateLen);

    /**
     * @brief Firma un mensaje y codifica el resultado en una cadena Base64 plana.
     * 
     * Realiza una firma digital utilizando el algoritmo **SHA-256** sobre los datos en \p pXml,
     * extrae el primer certificado válido del archivo PFX y convierte el bloque firmado PKCS#7 
     * resultante en texto legible Base64 de una sola línea continua (sin saltos de línea CRLF).
     *
     * @param[in]  pXml       Puntero al mensaje de texto o estructura (ej. XML) que se desea firmar.
     * @param[in]  xmlLen     Longitud en bytes/caracteres de los datos apuntados por \p pXml.
     * @param[in]  pPfxPath   Ruta al archivo de certificado PFX (.pfx o .p12).
     * @param[in]  pfxLen     Longitud en caracteres de la cadena de texto \p pPfxPath.
     * @param[in]  pPwd       Contraseña para descifrar y abrir el almacén PFX (puede ser NULL si no tiene).
     * @param[in]  pwdLen     Longitud en caracteres de la cadena \p pPwd.
     * 
     * @return **char*** Puntero a la cadena de texto ANSI terminada en nulo ('\0') que contiene el Base64.
     * @return **NULL**  Si los parámetros son inválidos, el PFX falló al abrirse o la codificación falló.
     * 
     * @warning La memoria del string devuelto es asignada internamente mediante `malloc()`. El llamador tiene la 
     *          estricta obligación de liberar este puntero invocando a \ref Cert_Free para evitar fugas de memoria (Memory Leaks).
     * 
     * @note La cadena devuelta es segura para ser transportada en payloads JSON o tags XML directamente, 
     *       ya que no contiene encabezados PEM ni retornos de carro automáticos.
     * 
     * @sa Cert_Free, Cert_SignMessageBin
     */
    CORE_API char *Cert_SignMessage(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen);

    /**
     * @brief Firma un mensaje y devuelve el bloque binario PKCS#7 / CMS resultante.
     *
     * Realiza una firma digital utilizando el algoritmo **SHA-256** sobre los datos provistos en \p pXml,
     * extrayendo de forma automática el primer certificado válido que se encuentre dentro del archivo PFX especificado.
     *
     * @param[in]  pXml           Puntero a los datos o mensaje de texto (por ejemplo, XML) que se desea firmar.
     * @param[in]  xmlLen         Tamaño en bytes de los datos apuntados por \p pXml.
     * @param[in]  pPfxPath       Ruta al archivo de certificado PFX (.pfx o .p12).
     * @param[in]  pfxLen         Longitud en caracteres de la cadena \p pPfxPath.
     * @param[in]  pPwd           Contraseña para descifrar y abrir el almacén PFX.
     * @param[in]  pwdLen         Longitud en caracteres de la cadena \p pPwd.
     * @param[out] outSignedLen   Puntero a una variable donde se escribirá el **tamaño exacto en bytes**
     *                            del bloque binario generado. No puede ser NULL.
     *
     * @return **BYTE*** Puntero al buffer nativo asignado en memoria dinámica que contiene la firma PKCS#7.
     * @return **NULL**  Si los parámetros son inválidos, el PFX no pudo abrirse o falló la firma criptográfica.
     *
     * @warning La memoria del buffer retornado es asignada internamente mediante `malloc()`. El llamador tiene la
     *          estricta obligación de liberar este puntero invocando a \ref Cert_Free para evitar fugas de memoria (Memory Leaks).
     *
     * @sa Cert_Free
     */
    CORE_API BYTE *Cert_SignMessageB(
        const char *pXml,
        int xmlLen,
        const char *pPfxPath,
        int pfxLen,
        const char *pPwd,
        int pwdLen,
        DWORD *outSignedLen);

    /**
     * @brief Libera la memoria dinámica asignada por las funciones de la API Core.
     *
     * Debe utilizarse para liberar los buffers de datos binarios o cadenas de texto que hayan sido
     * devueltos por funciones como \ref Cert_SignMessageBin.
     *
     * @param[in] ptr Puntero a la memoria nativa que se desea liberar. Si es NULL, la función no hace nada.
     */
    CORE_API void Cert_Free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif // CORE_CERTS_H

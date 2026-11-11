#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
 
#define CORE_API __declspec(dllimport)  

CORE_API int Cert_GetExpiry(const char *pPath, int pathLen, const char *pPwd, int pwdLen, char *outputDate, size_t maxDateLen);
CORE_API char *Cert_SignMessage(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen);
CORE_API BYTE *Cert_SignMessageB(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen, DWORD *outSignedLen);
CORE_API void Cert_Free(void *ptr);


int main() {
    // --- CONFIGURACIÓN DE PRUEBA ---
    const char *pfxPath = "certificado.pfx";
    const char *pfxPwd = "tu_password_aqui";
    const char *xmlPayload = "<Factura><Id>12345</Id><Total>150.00</Total></Factura>";

    int pfxLen = (int)strlen(pfxPath);
    int pwdLen = (int)strlen(pfxPwd);
    int xmlLen = (int)strlen(xmlPayload);

    printf("=== INICIANDO PRUEBA DE CORE_API EN C ===\n\n");

    // -------------------------------------------------------------------------
    // 1. PROBAR: Cert_GetExpiry
    // -------------------------------------------------------------------------
    printf("[1/3] Extrayendo fecha de vencimiento...\n");
    char dateBuffer[64];
    memset(dateBuffer, 0, sizeof(dateBuffer));

    int expiryResult = Cert_GetExpiry(pfxPath, pfxLen, pfxPwd, pwdLen, dateBuffer, sizeof(dateBuffer));

    if (expiryResult == 1) {
        printf("-> Exito. El certificado vence el: %s\n\n", dateBuffer);
    } else {
        printf("-> Error al extraer la fecha de vencimiento.\n\n");
    }

    // -------------------------------------------------------------------------
    // 2. PROBAR: Cert_SignMessage (Retorna Base64)
    // -------------------------------------------------------------------------
    printf("[2/3] Firmando XML y codificando en Base64 plano...\n");
    char *base64Result = Cert_SignMessage(xmlPayload, xmlLen, pfxPath, pfxLen, pfxPwd, pwdLen);

    if (base64Result != NULL) {
        printf("-> Exito. Firma Base64 generada (Primeros 80 caracteres):\n");
        
        // Imprimir de forma segura los primeros 80 caracteres para no llenar la consola
        printf("%.80s...\n", base64Result);
        printf("Longitud total de la cadena: %zu caracteres.\n\n", strlen(base64Result));

        // Liberamos obligatoriamente usando tu función exportada
        Cert_Free(base64Result);
    } else {
        printf("-> Error al firmar el mensaje en formato Base64.\n\n");
    }

    // -------------------------------------------------------------------------
    // 3. PROBAR: Cert_SignMessageBin (Retorna Bloque Binario PKCS#7)
    // -------------------------------------------------------------------------
    printf("[3/3] Firmando XML y extrayendo el bloque binario PKCS#7...\n");
    DWORD signedBinLen = 0;
    BYTE *binResult = Cert_SignMessageBin(xmlPayload, xmlLen, pfxPath, pfxLen, pfxPwd, pwdLen, &signedBinLen);

    if (binResult != NULL && signedBinLen > 0) {
        printf("-> Exito. Bloque binario creado con éxito.\n");
        printf("Tamaño total de la firma binaria: %lu bytes.\n\n", signedBinLen);

        // Opcional: Puedes guardar el binario generado en un archivo local .p7s
        FILE *file = fopen("firma.p7s", "wb");
        if (file) {
            fwrite(binResult, 1, signedBinLen, file);
            fclose(file);
            printf("Archivo 'firma.p7s' guardado exitosamente en el disco.\n\n");
        }

        // Liberamos obligatoriamente usando tu función exportada
        Cert_Free(binResult);
    } else {
        printf("-> Error al firmar el mensaje en formato binario.\n\n");
    }

    printf("=== FIN DEL PROGRAMA ===\n");
    return 0;
}

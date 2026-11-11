* =============================================================================
* EJEMPLO PRÁCTICO DE INTEGRACIÓN DE CORE_API EN VISUAL FOXPRO
* =============================================================================
CLEAR
SET DEVELOPMENT ON

* --- CONFIGURACIÓN DE RUTAS ---
* Asegúrate de que TuLibreria.dll esté en el mismo directorio o en el PATH de Windows
LOCAL lcDll, lcPfxPath, lcPfxPwd, lcXmlPayload
lcDll        = "libcerts.dll" 
lcPfxPath    = "certificado.pfx"
lcPfxPwd     = "tu_password_aqui"
lcXmlPayload = "<Factura><Id>12345</Id><Total>150.00</Total></Factura>"

? "=== INICIANDO PRUEBA DE CORE_API DESDE FOXPRO ==="
?

* -----------------------------------------------------------------------------
* DECLARACIÓN DE LAS FUNCIONES DE LA DLL (API NATIVA)
* -----------------------------------------------------------------------------
TRY
    * int Cert_GetExpiry(const char *pPath, int pathLen, const char *pPwd, int pwdLen, char *outputDate, size_t maxDateLen)
    DECLARE INTEGER Cert_GetExpiry IN (lcDll) ;
        STRING pPath, INTEGER pathLen, ;
        STRING pPwd, INTEGER pwdLen, ;
        STRING @outputDate, INTEGER maxDateLen

    * char *Cert_SignMessage(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen)
    DECLARE LONG Cert_SignMessage IN (lcDll) ;
        STRING pXml, INTEGER xmlLen, ;
        STRING pPfxPath, INTEGER pfxLen, ;
        STRING pPwd, INTEGER pwdLen

    * BYTE *Cert_SignMessageBin(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen, DWORD *outSignedLen)
    DECLARE LONG Cert_SignMessageBin IN (lcDll) ;
        STRING pXml, INTEGER xmlLen, ;
        STRING pPfxPath, INTEGER pfxLen, ;
        STRING pPwd, INTEGER pwdLen, ;
        LONG @outSignedLen

    * void Cert_Free(void *ptr)
    DECLARE Cert_Free IN (lcDll) LONG ptr

    * Función de la API de Windows para copiar memoria desde un puntero nativo a FoxPro
    DECLARE RtlMoveMemory IN kernel32 ;
        STRING @Destination, LONG Source, LONG nLength

CATCH TO oAsmError
    ? "Error al declarar las funciones de la DLL. Verifique que el archivo exista."
    ? oAsmError.Message
    RETURN
ENDTRY


* =============================================================================
* 1. PROBAR: Cert_GetExpiry
* =============================================================================
? "[1/3] Extrayendo fecha de vencimiento..."

* Preparamos un buffer de texto vacío de 64 bytes para recibir la fecha
LOCAL lcOutputDate, lnExpiryResult
lcOutputDate = SPACE(64) 

lnExpiryResult = Cert_GetExpiry(;
    lcPfxPath, LEN(lcPfxPath), ;
    lcPfxPwd, LEN(lcPfxPwd), ;
    @lcOutputDate, LEN(lcOutputDate))

IF lnExpiryResult = 1
    * Limpiamos los caracteres nulos CHR(0) y espacios sobrantes que devuelva C
    lcOutputDate = ALLTRIM(STRTRAN(lcOutputDate, CHR(0), ""))
    ? "-> Exito. Vence el:", lcOutputDate
ELSE
    ? "-> Error al extraer la fecha de vencimiento."
ENDIF
?


* =============================================================================
* 2. PROBAR: Cert_SignMessage (Retorna Base64 como puntero C-String)
* =============================================================================
? "[2/3] Firmando XML y obteniendo Base64 plano..."

LOCAL lnPtrBase64, lcBase64Final
lnPtrBase64 = Cert_SignMessage(;
    lcXmlPayload, LEN(lcXmlPayload), ;
    lcPfxPath, LEN(lcPfxPath), ;
    lcPfxPwd, LEN(lcPfxPwd))

IF lnPtrBase64 # 0
    * Como no sabemos el tamaño exacto del Base64, leemos un bloque inicial grande (ej: 8192 bytes)
    * y truncamos el string en el primer caracter nulo CHR(0)
    LOCAL lcTempBuf, lnPosNulo
    lcTempBuf = SPACE(8192)
    RtlMoveMemory(@lcTempBuf, lnPtrBase64, LEN(lcTempBuf))
    
    lnPosNulo = AT(CHR(0), lcTempBuf)
    IF lnPosNulo > 0
        lcBase64Final = LEFT(lcTempBuf, lnPosNulo - 1)
    ELSE
        lcBase64Final = lcTempBuf
    ENDIF
    
    ? "-> Exito. Firma Base64 generada (Primeros 60 chars):"
    ? LEFT(lcBase64Final, 60) + "..."
    ? "Longitud total:", LEN(lcBase64Final), "caracteres."
    
    * Liberamos OBLIGATORIAMENTE la memoria nativa
    Cert_Free(lnPtrBase64)
ELSE
    ? "-> Error al firmar el mensaje (Base64)."
ENDIF
?


* =============================================================================
* 3. PROBAR: Cert_SignMessageBin (Retorna Bloque Binario PKCS#7 mediante puntero)
* =============================================================================
? "[3/3] Firmando XML y obteniendo el bloque binario crudo..."

LOCAL lnPtrBin, lnOutSignedLen, lcBinFinal
lnOutSignedLen = 0

lnPtrBin = Cert_SignMessageBin(;
    lcXmlPayload, LEN(lcXmlPayload), ;
    lcPfxPath, LEN(lcPfxPath), ;
    lcPfxPwd, LEN(lcPfxPwd), ;
    @lnOutSignedLen)

IF lnPtrBin # 0 AND lnOutSignedLen > 0
    * En este caso sí conocemos el tamaño exacto gracias a lnOutSignedLen
    lcBinFinal = SPACE(lnOutSignedLen)
    
    * Copiamos los bytes crudos directamente a nuestra variable de FoxPro
    RtlMoveMemory(@lcBinFinal, lnPtrBin, lnOutSignedLen)
    
    ? "-> Exito. Bloque binario recuperado correctamente."
    ? "Tamaño de la firma binaria:", LEN(lcBinFinal), "bytes."
    
    * Opcional: Puedes guardar el binario directo en un archivo .p7s en disco
    * STRTOFILE(lcBinFinal, "firma.p7s")
    * ? "Archivo 'firma.p7s' guardado."
    
    * Liberamos OBLIGATORIAMENTE la memoria nativa
    Cert_Free(lnPtrBin)
ELSE
    ? "-> Error al firmar el mensaje (Binario)."
ENDIF

?
? "=== FIN DEL PROGRAMA ==="

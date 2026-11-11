<?php
// === CONFIGURACIÓN DE PRUEBA ===
$dllPath = "libcert.dll"; // Ruta completa o relativa a tu DLL
$certPath = "certificado.pfx";
$certPwd = "tu_password_aqui";
$xmlPayload = "<Factura><Id>12345</Id><Total>150.00</Total></Factura>";

echo "=== INICIANDO PRUEBA DE CORE_API EN PHP (FFI) ===\n\n";

if (!extension_loaded('ffi')) {
    die("[ERROR CRÍTICO] La extensión FFI no está cargada. Actívala en tu php.ini con ffi.enable=true\n");
}

try { 

    $ffi = FFI::cdef("
        int Cert_GetExpiry(const char *pPath, int pathLen, const char *pPwd, int pwdLen, char *outputDate, size_t maxDateLen);
        char *Cert_SignMessage(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen);
        unsigned char *Cert_SignMessageB(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen, unsigned long *outSignedLen);
        void Cert_Free(void *ptr);
    ", $dllPath);

} catch (FFI\Exception $e) {
    die("[ERROR AL CARGAR DLL]: " . $e->getMessage() . "\n");
}

// -------------------------------------------------------------------------
// 1. PROBAR: Cert_GetExpiry
// -------------------------------------------------------------------------
echo "[1/3] Extrayendo fecha de vencimiento...\n";

// Reservamos un buffer de caracteres nativo en C de 64 bytes
$dateBuffer = FFI::new("char[64]");

$expiryResult = $ffi->Cert_GetExpiry(
    $certPath, strlen($certPath),
    $certPwd, strlen($certPwd),
    $dateBuffer, 64
);

if ($expiryResult === 1) {
    // FFI::string convierte el buffer char* de C a un string nativo de PHP
    echo "-> Éxito. El certificado vence el: " . FFI::string($dateBuffer) . "\n\n";
} else {
    echo "-> Error al extraer la fecha de vencimiento.\n\n";
}


// -------------------------------------------------------------------------
// 2. PROBAR: Cert_SignMessage (Retorna Base64 como char*)
// -------------------------------------------------------------------------
echo "[2/3] Firmando XML y codificando en Base64 plano...\n";

$pBase64Str = $ffi->Cert_SignMessage(
    $xmlPayload, strlen($xmlPayload),
    $certPath, strlen($certPath),
    $certPwd, strlen($certPwd)
);

if ($pBase64Str !== null && !FFI::isNull($pBase64Str)) { 

    $base64Resultado = FFI::string($pBase64Str);
    
    echo "-> Éxito. Firma Base64 generada (Primeros 80 caracteres):\n";
    echo substr($base64Resultado, 0, 80) . "...\n";
    echo "Longitud total: " . strlen($base64Resultado) . " caracteres.\n\n";
 
    $ffi->Cert_Free($pBase64Str);
} else {
    echo "-> Error al firmar el mensaje en formato Base64.\n\n";
}


// -------------------------------------------------------------------------
// 3. PROBAR: Cert_SignMessageB (Retorna Bloque Binario PKCS#7)
// -------------------------------------------------------------------------
echo "[3/3] Firmando XML y extrayendo el bloque binario PKCS#7...\n";
 
$outSignedLen = FFI::new("unsigned long");

$pBinResult = $ffi->Cert_SignMessageB(
    $xmlPayload, strlen($xmlPayload),
    $certPath, strlen($certPath),
    $certPwd, strlen($certPwd),
    FFI::addr($outSignedLen) // Enviamos la dirección de memoria (equivalente a & en C)
);

if ($pBinResult !== null && !FFI::isNull($pBinResult) && $outSignedLen->cdata > 0) {
    $binSize = $outSignedLen->cdata;
    
     $binResultado = FFI::string($pBinResult, $binSize);
    
    echo "-> Éxito. Bloque binario creado con éxito.\n";
    echo "Tamaño de la firma binaria: " . strlen($binResultado) . " bytes.\n\n";
 
    file_put_contents("firma.p7s", $binResultado);
    echo "Archivo 'firma.p7s' guardado exitosamente en el disco.\n\n";
 
    $ffi->Cert_Free($pBinResult);
} else {
    echo "-> Error al firmar el mensaje en formato binario.\n\n";
}

echo "=== FIN DEL PROGRAMA ===\n";
?>

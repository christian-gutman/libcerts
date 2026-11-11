const ffi = require('ffi-napi');
const ref = require('ref-napi');
const fs = require('fs');

// --- CONFIGURACIÓN DE TIPOS (Mapeo de C a Node.js) ---
const charPtr = ref.types.CString; // char* terminado en nulo
const intType = ref.types.int;     // int estándar
const sizeType = ref.types.size_t; // size_t para longitudes
const dwordType = ref.types.ulong; // DWORD de Windows mapea a unsigned long
const voidPtr = ref.refType(ref.types.void); // void* para punteros genéricos
const dwordPtr = ref.refType(dwordType);     // DWORD* para paso por referencia

// --- CONFIGURACIÓN DE PRUEBA ---
const dllPath = 'TuLibreria.dll'; // Ruta completa o relativa a tu archivo DLL
const certPath = 'certificado.pfx';
const certPwd = 'tu_password_aqui';
const xmlPayload = '<Factura><Id>12345</Id><Total>150.00</Total></Factura>';

console.log('=== INICIANDO PRUEBA DE CORE_API EN NODE.JS ===\n');

// 1. Instanciar y cargar la DLL mapeando sus funciones
let certApi;
try {
    certApi = ffi.Library(dllPath, {
        'Cert_GetExpiry': [intType, [charPtr, intType, charPtr, intType, charPtr, sizeType]],
        'Cert_SignMessage': [charPtr, [charPtr, intType, charPtr, intType, charPtr, intType]],
        'Cert_SignMessageB': [voidPtr, [charPtr, intType, charPtr, intType, charPtr, intType, dwordPtr]],
        'Cert_Free': [ref.types.void, [voidPtr]]
    });
} catch (err) {
    console.error('[ERROR AL CARGAR DLL]: Asegúrate de que la arquitectura (x64/x86) coincida con tu Node.js.');
    console.error(err.message);
    process.exit(1);
}

// -------------------------------------------------------------------------
// 1. PROBAR: Cert_GetExpiry
// -------------------------------------------------------------------------
console.log('[1/3] Extrayendo fecha de vencimiento...');

// Asignamos un buffer de 64 bytes para recibir el string de la fecha
const dateBuffer = Buffer.alloc(64);

const expiryResult = certApi.Cert_GetExpiry(
    certPath, certPath.length,
    certPwd, certPwd.length,
    dateBuffer, dateBuffer.length
);

if (expiryResult === 1) {
    // ref.readCString lee el buffer deteniéndose en el carácter nulo \0
    const fechaFinal = ref.readCString(dateBuffer, 0);
    console.log(`-> Éxito. El certificado vence el: ${fechaFinal}\n`);
} else {
    console.log('-> Error al extraer la fecha de vencimiento.\n');
}

// -------------------------------------------------------------------------
// 2. PROBAR: Cert_SignMessage (Retorna Base64 como un string C)
// -------------------------------------------------------------------------
console.log('[2/3] Firmando XML y codificando en Base64 plano...');

const pBase64Str = certApi.Cert_SignMessage(
    xmlPayload, xmlPayload.length,
    certPath, certPath.length,
    certPwd, certPwd.length
);

if (pBase64Str && !pBase64Str.isNull()) {
    // ffi-napi convierte automáticamente el char* de retorno en un string de JS
    // Sin embargo, el puntero subyacente sigue existiendo en el heap de C.
    const base64Resultado = ref.readCString(pBase64Str, 0);
    
    console.log('-> Éxito. Firma Base64 generada (Primeros 80 caracteres):');
    console.log(`${base64Resultado.substring(0, 80)}...`);
    console.log(`Longitud total: ${base64Resultado.length} caracteres.\n`);
 
    certApi.Cert_Free(pBase64Str);
} else {
    console.log('-> Error al firmar el mensaje en formato Base64.\n');
}

// -------------------------------------------------------------------------
// 3. PROBAR: Cert_SignMessageB (Retorna Bloque Binario PKCS#7)
// -------------------------------------------------------------------------
console.log('[3/3] Firmando XML y extrayendo el bloque binario PKCS#7...');
 
const pOutSignedLen = ref.alloc(dwordType);

const pBinResult = certApi.Cert_SignMessageB(
    xmlPayload, xmlPayload.length,
    certPath, certPath.length,
    certPwd, certPwd.length,
    pOutSignedLen  
);

if (pBinResult && !pBinResult.isNull()) { 
    const binSize = pOutSignedLen.deref();
    
    if (binSize > 0) {
          const binBuffer = ref.reinterpret(pBinResult, binSize, 0);
        
        console.log('-> Éxito. Bloque binario creado con éxito.');
        console.log(`Tamaño de la firma binaria: ${binBuffer.length} bytes.\n`);
 
        fs.writeFileSync('firma.p7s', binBuffer);
        console.log("Archivo 'firma.p7s' guardado exitosamente en el disco.\n");
    }
 
    certApi.Cert_Free(pBinResult);
} else {
    console.log('-> Error al firmar el mensaje en formato binario.\n');
}

console.log('=== FIN DEL PROGRAMA ===');

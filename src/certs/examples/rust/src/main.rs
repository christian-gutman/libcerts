use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::fs::File;
use std::io::Write;
 
#[link(name = "libcerts")]
extern "C" {
    fn Cert_GetExpiry(
        pPath: *const c_char,
        pathLen: c_int,
        pPwd: *const c_char,
        pwdLen: c_int,
        outputDate: *mut c_char,
        maxDateLen: usize,
    ) -> c_int;

    fn Cert_SignMessage(
        pXml: *const c_char,
        xmlLen: c_int,
        pPfxPath: *const c_char,
        pfxLen: c_int,
        pPwd: *const c_char,
        pwdLen: c_int,
    ) -> *mut c_char;

    fn Cert_SignMessageB(
        pXml: *const c_char,
        xmlLen: c_int,
        pPfxPath: *const c_char,
        pfxLen: c_int,
        pPwd: *const c_char,
        pwdLen: c_int,
        outSignedLen: *mut u32,
    ) -> *mut c_uchar;

    fn Cert_Free(ptr: *mut c_void);
}

fn main() { 
    let cert_path = "certificado.pfx";
    let cert_pwd = "tu_password_aqui";
    let xml_payload = "<Factura><Id>12345</Id><Total>150.00</Total></Factura>";

    println!("=== INICIANDO PRUEBA DE CORE_API EN RUST ===\n");
 
    let c_cert_path = CString::new(cert_path).unwrap();
    let c_cert_pwd = CString::new(cert_pwd).unwrap();
    let c_xml_payload = CString::new(xml_payload).unwrap();

    // -------------------------------------------------------------------------
    // 1. PROBAR: Cert_GetExpiry
    // -------------------------------------------------------------------------
    println!("[1/3] Extrayendo fecha de vencimiento...");
    let mut date_buffer = vec![0u8; 64];  

    let expiry_result = unsafe {
        Cert_GetExpiry(
            c_cert_path.as_ptr(),
            cert_path.len() as c_int,
            c_cert_pwd.as_ptr(),
            cert_pwd.len() as c_int,
            date_buffer.as_mut_ptr() as *mut c_char,
            date_buffer.len(),
        )
    };

    if expiry_result == 1 {
 
        if let Ok(c_str) = CStr::from_bytes_until_nul(&date_buffer) {
            println!("-> Éxito. El certificado vence el: {}\n", c_str.to_string_lossy());
        }
    } else {
        println!("-> Error al extraer la fecha de vencimiento.\n");
    }

    // -------------------------------------------------------------------------
    // 2. PROBAR: Cert_SignMessage (Retorna Base64 como puntero mallocado)
    // -------------------------------------------------------------------------
    println!("[2/3] Firmando XML y codificando en Base64 plano...");
    
    let p_base64 = unsafe {
        Cert_SignMessage(
            c_xml_payload.as_ptr(),
            xml_payload.len() as c_int,
            c_cert_path.as_ptr(),
            cert_path.len() as c_int,
            c_cert_pwd.as_ptr(),
            cert_pwd.len() as c_int,
        )
    };

    if !p_base64.is_null() {
        unsafe { 

            let c_str = CStr::from_ptr(p_base64);
            let base64_rust = c_str.to_string_lossy();
            
            println!("-> Éxito. Firma Base64 generada (Primeros 80 caracteres):");
            println!("{}...", &base64_rust[..80.min(base64_rust.len())]);
            println!("Longitud total: {} caracteres.\n", base64_rust.len());
 
            Cert_Free(p_base64 as *mut c_void);
        }
    } else {
        println!("-> Error al firmar el mensaje en formato Base64.\n");
    }

    // -------------------------------------------------------------------------
    // 3. PROBAR: Cert_SignMessageBin (Retorna Bloque Binario PKCS#7)
    // -------------------------------------------------------------------------
    println!("[3/3] Firmando XML y extrayendo el bloque binario PKCS#7...");
    let mut signed_bin_len: u32 = 0;

    let p_bin = unsafe {
        Cert_SignMessageBin(
            c_xml_payload.as_ptr(),
            xml_payload.len() as c_int,
            c_cert_path.as_ptr(),
            cert_path.len() as c_int,
            c_cert_pwd.as_ptr(),
            cert_pwd.len() as c_int,
            &mut signed_bin_len,
        )
    };

    if !p_bin.is_null() && signed_bin_len > 0 {
        unsafe {
            // Creamos un slice de Rust apuntando directamente a la memoria nativa
            let bin_slice = std::slice::from_raw_parts(p_bin, signed_bin_len as usize);
            
            println!("-> Éxito. Bloque binario creado con éxito.");
            println!("Tamaño de la firma binaria: {} bytes.\n", bin_slice.len());

            // Opcional: Escribir los bytes directamente a un archivo en disco (.p7s)
            if let Ok(mut file) = File::create("firma.p7s") {
                let _ = file.write_all(bin_slice);
                println!("Archivo 'firma.p7s' guardado exitosamente en el disco.\n");
            }

            // LIBERACIÓN OBLIGATORIA: Devolvemos el control a tu DLL para liberar el malloc
            Cert_Free(p_bin as *mut c_void);
        }
    } else {
        println!("-> Error al firmar el mensaje en formato binario.\n");
    }

    println!("=== FIN DEL PROGRAMA ===");
}

fn main() {
    // Indica a Rust dónde buscar el archivo .lib de tu DLL (ej: el directorio actual)
    println!("cargo:rustc-link-search=native=."); 
    // Enlaza con libcerts.lib
    println!("cargo:rustc-link-lib=dylib=libcerts");
}
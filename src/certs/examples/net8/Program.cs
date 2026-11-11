using System.Runtime.InteropServices;
using System.Text;

const string DllPath = "libcerts.dll";
const string CertPath = "certificado.pfx";
const string CertPassword = "tu_password_aqui";

const string XmlPayload = "<Factura><Id>12345</Id><Total>150.00</Total></Factura>";

Console.WriteLine("=== INICIANDO PRUEBA DE CORE_API (PINVOKE) ===\n");

try
{
    // -------------------------------------------------------------------------
    // 1. OBTENER FECHA DE VENCIMIENTO
    // -------------------------------------------------------------------------
    Console.WriteLine("[1/3] Extrayendo fecha de vencimiento...");
    StringBuilder dateBuffer = new StringBuilder(64);

    int expiryResult = CertApiNative.Cert_GetExpiry(
        CertPath, CertPath.Length,
        CertPassword, CertPassword.Length,
        dateBuffer, (UIntPtr)dateBuffer.Capacity
    );

    if (expiryResult == 1)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✓ Éxito. El certificado vence el: {dateBuffer}\n");
        Console.ResetColor();
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("✗ Error al extraer la fecha de vencimiento.\n");
        Console.ResetColor();
    }

    // -------------------------------------------------------------------------
    // 2. FIRMAR MENSAJE Y OBTENER BASE64 (Cert_SignMessage)
    // -------------------------------------------------------------------------
    Console.WriteLine("[2/3] Firmando XML y codificando en Base64 plano...");

    IntPtr pBase64Str = CertApiNative.Cert_SignMessage(
        XmlPayload, XmlPayload.Length,
        CertPath, CertPath.Length,
        CertPassword, CertPassword.Length
    );

    if (pBase64Str != IntPtr.Zero)
    {
        try
        {
            string base64Resultado = Marshal.PtrToStringAnsi(pBase64Str)!;

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("✓ Éxito. Firma Base64 generada:");
            Console.ResetColor();
            // Mostramos solo los primeros 100 caracteres para no saturar la pantalla
            Console.WriteLine(base64Resultado.Length > 100 ? base64Resultado[..100] + "..." : base64Resultado);
            Console.WriteLine($"Longitud total de la cadena: {base64Resultado.Length} caracteres.\n");
        }
        finally
        {
            // Garantizamos la liberación en el Heap de C
            CertApiNative.Cert_Free(pBase64Str);
        }
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("✗ Error al firmar el mensaje en formato Base64.\n");
        Console.ResetColor();
    }

    // -------------------------------------------------------------------------
    // 3. FIRMAR MENSAJE EN BINARIO PURO (Cert_SignMessageB)
    // -------------------------------------------------------------------------
    Console.WriteLine("[3/3] Firmando XML y extrayendo el bloque binario PKCS#7...");

    IntPtr pBinResult = CertApiNative.Cert_SignMessageB(
        XmlPayload, XmlPayload.Length,
        CertPath, CertPath.Length,
        CertPassword, CertPassword.Length,
        out uint signedBinLen
    );

    if (pBinResult != IntPtr.Zero && signedBinLen > 0)
    {
        try
        {
            // Reservamos memoria administrada en .NET y copiamos los bytes crudos desde C
            byte[] managedBytes = new byte[signedBinLen];
            Marshal.Copy(pBinResult, managedBytes, 0, (int)signedBinLen);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✓ Éxito. Bloque binario firmado creado con éxito.");
            Console.ResetColor();
            Console.WriteLine($"Tamaño del archivo de firma binaria: {managedBytes.Length} bytes.");

            // Opcional: Guardar la firma binaria directamente a un archivo (.p7s)
            File.WriteAllBytes("firma.p7s", managedBytes);
            Console.WriteLine("Archivo 'firma.p7s' guardado en el disco.");
        }
        finally
        {
            // Liberación estricta de la memoria nativa asignada con malloc
            CertApiNative.Cert_Free(pBinResult);
        }
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("✗ Error al firmar el mensaje en formato binario.\n");
        Console.ResetColor();
    }
}
catch (DllNotFoundException)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"\n[ERROR CRÍTICO] No se encontró el archivo '{DllPath}'.");
    Console.WriteLine("Asegúrate de compilar tu DLL de C y copiarla en la carpeta de salida del ejecutable de C#.");
    Console.ResetColor();
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"\n[ERROR]: {ex.Message}");
    Console.ResetColor();
}

Console.WriteLine("\n=== FIN DEL PROGRAMA ===");


// =============================================================================
// CAPA DE INTEROP (PINVOKE)
// =============================================================================
public static class CertApiNative
{
    // Nombre o ruta de tu archivo compilado en C (ej: "libcerts.dll")
    private const string DllName = "libcerts.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int Cert_GetExpiry(
        string pPath,
        int pathLen,
        string pPwd,
        int pwdLen,
        StringBuilder outputDate,
        UIntPtr maxDateLen
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr Cert_SignMessage(
        string pXml,
        int xmlLen,
        string pPfxPath,
        int pfxLen,
        string pPwd,
        int pwdLen
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr Cert_SignMessageB(
        string pXml,
        int xmlLen,
        string pPfxPath,
        int pfxLen,
        string pPwd,
        int pwdLen,
        out uint outSignedLen
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void Cert_Free(IntPtr ptr);
}

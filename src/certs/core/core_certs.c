#include "core_certs.h"
 

#ifndef CRYPT_STRING_BASE64RAW
    #define CRYPT_STRING_BASE64RAW 0x00000009
#endif
  
int Cert_GetExpiry(const char *pPath, int pathLen, const char *pPwd, int pwdLen, char *outputDate, size_t maxDateLen)
{
    if (!pPath || pathLen <= 0 || !outputDate) return 0;

    wchar_t *wPath = StrAutoToUnicode(pPath, pathLen, NULL);
    if (!wPath) return 0;

    wchar_t *wPwd = (pPwd && pwdLen > 0) ? StrAutoToUnicode(pPwd, pwdLen, NULL) : NULL;

    DWORD fileSize = 0;
    BYTE *fileBytes = ReadFileBytesC(wPath, &fileSize);
    free(wPath);

    if (!fileBytes || fileSize == 0) {
        if (wPwd) free(wPwd);
        return 0;
    }

    PCCERT_CONTEXT pCertContext = NULL;
    HCERTSTORE hStore = NULL;
    CRYPT_DATA_BLOB pfxBlob = { fileSize, fileBytes };

    if (PFXIsPFXBlob(&pfxBlob)) {
        hStore = PFXImportCertStore(&pfxBlob, wPwd ? wPwd : L"", CRYPT_EXPORTABLE);
        if (hStore) {
            pCertContext = CertEnumCertificatesInStore(hStore, NULL);
        }
    }

    if (!pCertContext) {
        BOOL isPem = FALSE;
        if (fileSize > 27) {
            for (DWORD i = 0; i <= fileSize - 27; i++) {
                if (strncmp((char *)(fileBytes + i), "-----BEGIN CERTIFICATE-----", 27) == 0) {
                    isPem = TRUE;
                    break;
                }
            }
        }

        if (isPem) {
            DWORD derLen = 0;
            if (CryptStringToBinaryA((char *)fileBytes, fileSize, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL)) {
                BYTE *derBytes = (BYTE *)malloc(derLen);
                if (derBytes) {
                    if (CryptStringToBinaryA((char *)fileBytes, fileSize, CRYPT_STRING_BASE64HEADER, derBytes, &derLen, NULL, NULL)) {
                        pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, derBytes, derLen);
                    }
                    free(derBytes);
                }
            }
        }

        if (!pCertContext) {
            pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, fileBytes, fileSize);
        }
    }

    free(fileBytes);
    if (wPwd) free(wPwd);

    if (!pCertContext) {
        if (hStore) CertCloseStore(hStore, 0);
        return 0;
    }

    FILETIME localFileTime = {0};
    SYSTEMTIME sysTime = {0};
    int success = 0;

    if (FileTimeToLocalFileTime(&pCertContext->pCertInfo->NotAfter, &localFileTime)) {
        if (FileTimeToSystemTime(&localFileTime, &sysTime)) {
            if (sprintf_s(outputDate, maxDateLen, "%04d-%02d-%02d %02d:%02d:%02d",
                          sysTime.wYear, sysTime.wMonth, sysTime.wDay,
                          sysTime.wHour, sysTime.wMinute, sysTime.wSecond) != -1) {
                success = 1;
            }
        }
    }

    CertFreeCertificateContext(pCertContext);
    if (hStore) CertCloseStore(hStore, 0);

    return success;
}

char *Cert_SignMessage(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen)
{
    if (!pXml || xmlLen <= 0 || !pPfxPath || pfxLen <= 0) return NULL;

    wchar_t *wPfxPath = StrAutoToUnicode(pPfxPath, pfxLen, NULL); // Asumo que esta función ya la tienes
    if (!wPfxPath) return NULL;

    wchar_t *wPwd = (pPwd && pwdLen > 0) ? StrAutoToUnicode(pPwd, pwdLen, NULL) : NULL;

    DWORD fileSize = 0;
    BYTE *fileBytes = ReadFileBytesC(wPfxPath, &fileSize); // Asumo que esta función ya la tienes
    free(wPfxPath);

    if (!fileBytes || fileSize == 0) {
        if (wPwd) free(wPwd);
        return NULL;
    }

    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pSignCert = NULL;
    CRYPT_DATA_BLOB pfxBlob = { fileSize, fileBytes };

    if (PFXIsPFXBlob(&pfxBlob)) {
        hStore = PFXImportCertStore(&pfxBlob, wPwd ? wPwd : L"", CRYPT_EXPORTABLE);
        if (hStore) {
            pSignCert = CertEnumCertificatesInStore(hStore, NULL);
        }
    }

    free(fileBytes);
    if (wPwd) free(wPwd);

    if (!pSignCert) {
        if (hStore) CertCloseStore(hStore, 0);
        return NULL;
    }

    CRYPT_SIGN_MESSAGE_PARA signPara = {0};
    signPara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = pSignCert;
    signPara.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256; // SHA-256

    const BYTE *rgpbToBeSigned[1] = { (const BYTE *)pXml };
    DWORD rgcbToBeSigned[1] = { (DWORD)xmlLen };
    DWORD cbSignedMsg = 0;
    char *base64Str = NULL;
    if (CryptSignMessage(&signPara, FALSE, 1, rgpbToBeSigned, rgcbToBeSigned, NULL, &cbSignedMsg)) {
        BYTE *signedBlob = (BYTE *)malloc(cbSignedMsg);
        if (signedBlob) {
            if (CryptSignMessage(&signPara, FALSE, 1, rgpbToBeSigned, rgcbToBeSigned, signedBlob, &cbSignedMsg))
            {
                DWORD base64Len = 0;
                DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
                if (CryptBinaryToStringA(signedBlob, cbSignedMsg, flags, NULL, &base64Len)) {
                    base64Str = (char *)malloc(base64Len); // CryptBinaryToStringA ya incluye el espacio para el '\0'
                    if (base64Str) {
                        if (!CryptBinaryToStringA(signedBlob, cbSignedMsg, flags, base64Str, &base64Len)) {
                            free(base64Str);
                            base64Str = NULL;
                        }
                    }
                }
            }
            free(signedBlob);
        }
    }

    if (pSignCert) CertFreeCertificateContext(pSignCert);
    if (hStore) CertCloseStore(hStore, 0);

    return base64Str;
}

BYTE *Cert_SignMessageB(
    const char *pXml, 
    int xmlLen, 
    const char *pPfxPath, 
    int pfxLen, 
    const char *pPwd, 
    int pwdLen, 
    DWORD *outSignedLen)
{ 
    if (!pXml || xmlLen <= 0 || !pPfxPath || pfxLen <= 0 || !outSignedLen) return NULL;
    
    *outSignedLen = 0; 

    wchar_t *wPfxPath = StrAutoToUnicode(pPfxPath, pfxLen, NULL);
    if (!wPfxPath) return NULL;

    wchar_t *wPwd = (pPwd && pwdLen > 0) ? StrAutoToUnicode(pPwd, pwdLen, NULL) : NULL;

    DWORD fileSize = 0;
    BYTE *fileBytes = ReadFileBytesC(wPfxPath, &fileSize);
    free(wPfxPath);

    if (!fileBytes || fileSize == 0) {
        if (wPwd) free(wPwd);
        return NULL;
    }

    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pSignCert = NULL;
    CRYPT_DATA_BLOB pfxBlob = { fileSize, fileBytes };

    if (PFXIsPFXBlob(&pfxBlob)) {
        hStore = PFXImportCertStore(&pfxBlob, wPwd ? wPwd : L"", CRYPT_EXPORTABLE);
        if (hStore) {
            pSignCert = CertEnumCertificatesInStore(hStore, NULL);
        }
    }

    free(fileBytes);
    if (wPwd) free(wPwd);

    if (!pSignCert) {
        if (hStore) CertCloseStore(hStore, 0);
        return NULL;
    }

    CRYPT_SIGN_MESSAGE_PARA signPara = {0};
    signPara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = pSignCert;
    signPara.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;

    const BYTE *rgpbToBeSigned[1] = { (const BYTE *)pXml };
    DWORD rgcbToBeSigned[1] = { (DWORD)xmlLen };
    DWORD cbSignedMsg = 0;
    BYTE *signedBlob = NULL;
 
    if (CryptSignMessage(&signPara, FALSE, 1, rgpbToBeSigned, rgcbToBeSigned, NULL, &cbSignedMsg)) {
 
        signedBlob = (BYTE *)malloc(cbSignedMsg);
        if (signedBlob) { 
            if (CryptSignMessage(&signPara, FALSE, 1, rgpbToBeSigned, rgcbToBeSigned, signedBlob, &cbSignedMsg)) {
 
                *outSignedLen = cbSignedMsg;
            } else { 
                free(signedBlob);
                signedBlob = NULL;
            }
        }
    }
 
    CertFreeCertificateContext(pSignCert);
    if (hStore) CertCloseStore(hStore, 0);

    return signedBlob;  
}

char *Cert_SignMessageB(const char *pXml, int xmlLen, const char *pPfxPath, int pfxLen, const char *pPwd, int pwdLen)
{
    if (!pXml || xmlLen <= 0 || !pPfxPath || pfxLen <= 0) return NULL;

    wchar_t *wPfxPath = StrAutoToUnicode(pPfxPath, pfxLen, NULL);
    if (!wPfxPath) return NULL;

    wchar_t *wPwd = (pPwd && pwdLen > 0) ? StrAutoToUnicode(pPwd, pwdLen, NULL) : NULL;

    DWORD fileSize = 0;
    BYTE *fileBytes = ReadFileBytesC(wPfxPath, &fileSize);
    free(wPfxPath);

    if (!fileBytes || fileSize == 0) {
        if (wPwd) free(wPwd);
        return NULL;
    }

    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pSignCert = NULL;
    CRYPT_DATA_BLOB pfxBlob = { fileSize, fileBytes };

    if (PFXIsPFXBlob(&pfxBlob)) {
        hStore = PFXImportCertStore(&pfxBlob, wPwd ? wPwd : L"", CRYPT_EXPORTABLE);
        if (hStore) {
            pSignCert = CertEnumCertificatesInStore(hStore, NULL);
        }
    }

    free(fileBytes);
    if (wPwd) free(wPwd);

    if (!pSignCert) {
        if (hStore) CertCloseStore(hStore, 0);
        return NULL;
    }

    CRYPT_SIGN_MESSAGE_PARA signPara = {0};
    signPara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    //new dwMsgEncodingType 
    signPara.dwMsgEncodingType  = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = pSignCert;
    signPara.HashAlgorithm.pszObjId = szOID_NIST_sha256;

    const BYTE *rgpbToBeSigned[1] = { (const BYTE *)pXml };
    DWORD rgcbToBeSigned[1] = { (DWORD)xmlLen };
    DWORD cbSignedMsg = 0;
    char *base64Str = NULL;

    if (CryptSignMessage(&signPara, FALSE, 1, rgpbToBeSigned, rgcbToBeSigned, NULL, &cbSignedMsg)) {
        BYTE *signedBlob = (BYTE *)malloc(cbSignedMsg);
        if (signedBlob) {
            if (CryptSignMessage(&signPara, FALSE, 1, rgpbToBeSigned, rgcbToBeSigned, signedBlob, &cbSignedMsg)) {
                DWORD base64Len = 0;
                if (CryptStringToBinaryA((const char *)signedBlob, cbSignedMsg, CRYPT_STRING_BASE64RAW, NULL, &base64Len, NULL, NULL)) {
                    base64Str = (char *)malloc(base64Len + 1);
                    if (base64Str) {
                        if (CryptStringToBinaryA((const char *)signedBlob, cbSignedMsg, CRYPT_STRING_BASE64RAW, (BYTE *)base64Str, &base64Len, NULL, NULL)) {
                            base64Str[base64Len] = '\0';
                        } else {
                            free(base64Str);
                            base64Str = NULL;
                        }
                    }
                }
            }
            free(signedBlob);
        }
    }

    CertFreeCertificateContext(pSignCert);
    if (hStore) CertCloseStore(hStore, 0);

    return base64Str;
}

void Cert_Free(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}
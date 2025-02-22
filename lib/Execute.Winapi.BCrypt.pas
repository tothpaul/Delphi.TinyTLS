unit Execute.Winapi.BCrypt;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface

uses
  Winapi.Windows,
  System.SysUtils;

const
  CRYPT32 = 'crypt32.dll';

  X509_ASN_ENCODING = $00000001;
  PKCS_7_ASN_ENCODING = $00010000;

  szOID_RSA             = '1.2.840.113549';
  szOID_NIST_AES128_CBC = '2.16.840.1.101.3.4.1.2';
  szOID_PKIX_KP_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
  szOID_SERVER_GATED_CRYPTO = '1.3.6.1.4.1.311.10.3.3';
  szOID_SGC_NETSCAPE        = '2.16.840.1.113730.4.1';
  szOID_PKIX_KP_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

  CERT_X500_NAME_STR = 3;

  CERT_NAME_STR_REVERSE_FLAG    = $02000000;
  CERT_NAME_STR_COMMA_FLAG      = $04000000;
  CERT_NAME_STR_CRLF_FLAG       = $08000000;
  CERT_NAME_STR_NO_QUOTING_FLAG = $10000000;
  CERT_NAME_STR_NO_PLUS_FLAG    = $20000000;
  CERT_NAME_STR_SEMICOLON_FLAG  = $40000000;

  CRYPT_DECODE_ALLOC_FLAG = $8000;

  CERT_CROSS_CERT_DIST_POINTS_PROP_ID = 23;
  CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID = 81;


  X509_ALTERNATE_NAME = LPCSTR(12);
  X509_SEQUENCE_OF_ANY = LPCSTR(34);
  PKCS_RSA_PRIVATE_KEY = LPCSTR(43);
  CNG_RSA_PRIVATE_KEY_BLOB = LPCSTR(83);

  USAGE_MATCH_TYPE_AND = 0;
  USAGE_MATCH_TYPE_OR  = 1;

  CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $40000000;

  CERT_CHAIN_POLICY_BASE              =LPCSTR(1);
  CERT_CHAIN_POLICY_AUTHENTICODE      =LPCSTR(2);
  CERT_CHAIN_POLICY_AUTHENTICODE_TS   =LPCSTR(3);
  CERT_CHAIN_POLICY_SSL               =LPCSTR(4);
  CERT_CHAIN_POLICY_BASIC_CONSTRAINTS =LPCSTR(5);
  CERT_CHAIN_POLICY_NT_AUTH           =LPCSTR(6);
  CERT_CHAIN_POLICY_MICROSOFT_ROOT    =LPCSTR(7);

  AUTHTYPE_CLIENT = 1;
  AUTHTYPE_SERVER = 2;

  // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status
  CERT_TRUST_NO_ERROR = 0;
  CERT_TRUST_IS_NOT_TIME_VALID = 1;
  CERT_TRUST_IS_REVOKED = 4;
  CERT_TRUST_IS_NOT_SIGNATURE_VALID = 8;
  CERT_TRUST_IS_NOT_VALID_FOR_USAGE = $10;
  CERT_TRUST_IS_UNTRUSTED_ROOT = $20;
  CERT_TRUST_REVOCATION_STATUS_UNKNOWN = $40;
  CERT_TRUST_IS_CYCLIC = $80;
  CERT_TRUST_INVALID_EXTENSION = $100;
  CERT_TRUST_INVALID_POLICY_CONSTRAINTS = $200;
  CERT_TRUST_INVALID_BASIC_CONSTRAINTS = $400;
  CERT_TRUST_INVALID_NAME_CONSTRAINTS = $800;
  CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = $1000;
  CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT = $2000;
  CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = $4000;
  CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT = $8000;
  CERT_TRUST_IS_OFFLINE_REVOCATION = $1000000;
  CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY = $2000000;
  CERT_TRUST_IS_EXPLICIT_DISTRUST = $4000000;
  CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT = $8000000;
  CERT_TRUST_HAS_WEAK_SIGNATURE = $100000;
  CERT_TRUST_IS_PARTIAL_CHAIN = $10000;
  CERT_TRUST_CTL_IS_NOT_TIME_VALID = $20000;
  CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID = $40000;
  CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE = $80000;

  URL_OID_CERTIFICATE_ISSUER = LPCSTR(1);
  URL_OID_CERTIFICATE_CRL_DIST_POINT = LPCSTR(2);
  URL_OID_CTL_ISSUER = LPCSTR(3);
  URL_OID_CTL_NEXT_UPDATE= LPCSTR(4);
  URL_OID_CRL_ISSUER = LPCSTR(5);
  URL_OID_CERTIFICATE_FRESHEST_CRL = LPCSTR(6);
  URL_OID_CRL_FRESHEST_CRL = LPCSTR(7);
  URL_OID_CROSS_CERT_DIST_POINT = LPCSTR(8);
  URL_OID_CERTIFICATE_OCSP = LPCSTR(9);
  URL_OID_CERTIFICATE_OCSP_AND_CRL_DIST_POINT = LPCSTR(10);
  URL_OID_CERTIFICATE_CRL_DIST_POINT_AND_OCSP = LPCSTR(11);
  URL_OID_CROSS_CERT_SUBJECT_INFO_ACCESS = LPCSTR(12);

  CRYPT_GET_URL_FROM_PROPERTY         = 1;
  CRYPT_GET_URL_FROM_EXTENSION        = 2;
  CRYPT_GET_URL_FROM_UNAUTH_ATTRIBUTE = 4;
  CRYPT_GET_URL_FROM_AUTH_ATTRIBUTE   = 8;

  CERT_CONTEXT_REVOCATION_TYPE = 1;

  CERT_VERIFY_REV_CHAIN_FLAG = 1;
  CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION = 2;
  CERT_VERIFY_REV_ACCUMULATIVE_TIMEOUT_FLAG = 4;
  CERT_VERIFY_REV_SERVER_OCSP_FLAG = 8;
  CERT_VERIFY_REV_NO_OCSP_FAILOVER_TO_CRL_FLAG  = 16;

  CRYPT_E_NO_REVOCATION_CHECK = $80092012;
  CRYPT_E_NOT_IN_REVOCATION_DATABASE = $80092014;

  PKCS12_INCLUDE_EXTENDED_PROPERTIES = $00000010;
  PKCS12_PREFER_CNG_KSP              = $00000100;
  PKCS12_ALLOW_OVERWRITE_KEY         = $00004000;
  PKCS12_NO_PERSIST_KEY              = $00008000;

function CertTrusts(Flags: DWORD): string;

type
  PPCCERT_CONTEXT = ^PCCERT_CONTEXT;

  HCRYPTPROV = type THandle;
  BCRYPT_KEY_HANDLE = THandle;
  BCRYPT_SECRET_HANDLE = THandle;
  HCRYPTKEY  = THandle;
  HCRYPTHASH = THandle;
  HCERTCHAINENGINE = THandle;
  HCERT_SERVER_OCSP_RESPONSE = THandle;


  CRYPT_ENCRYPT_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    hCryptProv: HCRYPTPROV;
    ContentEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    pvEncryptionAuxInfo: Pointer;
    dwFlags: DWORD;
    dwInnerContentType: DWORD;
  end;

  PFN_CRYPT_ALLOC = function(cbSize: size_t): Pointer; stdcall;
  PFN_CRYPT_FREE = procedure(pv: LPVOID); stdcall;

  CRYPT_DECODE_PARA = record
    cbSize: DWORD;
    pfnAlloc: PFN_CRYPT_ALLOC;
    pfnFree: PFN_CRYPT_FREE;
  end;
  PCRYPT_DECODE_PARA = ^CRYPT_DECODE_PARA;

  BCRYPT_KEY_LENGTHS_STRUCT = record
    dwMinLength: ULONG;
    dwMaxLength: ULONG;
    dwIncrement: ULONG;
  end;

  CTL_USAGE = record
    cUsageIdentifier: DWORD;
    rgpszUsageIdentifier: LPSTR;
  end;

  CERT_ENHKEY_USAGE = CTL_USAGE;
  PCERT_ENHKEY_USAGE = ^CERT_ENHKEY_USAGE;

  CERT_USAGE_MATCH = record
    dwType: DWORD;
    Usage: CERT_ENHKEY_USAGE;
  end;

  CERT_CHAIN_PARA = record
    cbSize: DWORD;
    RequestedUsage: CERT_USAGE_MATCH;
  end;
  PCERT_CHAIN_PARA = ^CERT_CHAIN_PARA;

  CERT_TRUST_STATUS = record
    dwErrorStatus: DWORD;
    dwInfoStatus: DWORD;
  end;

  CERT_REVOCATION_INFO = record
    cbSize: DWORD;
    dwRevocationResult: DWORD;
    pszRevocationOid: LPCSTR;
    pvOidSpecificInfo: LPVOID;
  end;
  PCERT_REVOCATION_INFO = ^CERT_REVOCATION_INFO;

  CERT_CHAIN_ELEMENT = record
    cbSize: DWORD;
    pCertContext: PCCERT_CONTEXT;
    TrustStatus: CERT_TRUST_STATUS;
    pRevocationInfo: PCERT_REVOCATION_INFO;
    pIssuanceUsage: PCERT_ENHKEY_USAGE;
    pApplicationUsage: PCERT_ENHKEY_USAGE;
    pwszExtendedErrorInfo: PChar;
  end;
  PCERT_CHAIN_ELEMENT = ^CERT_CHAIN_ELEMENT;

  CERT_TRUST_LIST_INFO = record
    cbSize: DWORD;
    pCtlEntry: PCTL_ENTRY;
    pCtlContext: PCCTL_CONTEXT;
  end;
  PCERT_TRUST_LIST_INFO = ^CERT_TRUST_LIST_INFO;

  CERT_SIMPLE_CHAIN = record
    cbSize: DWORD;
    TrustStatus: CERT_TRUST_STATUS;
    cElement: DWORD;
    rgpElement: ^PCERT_CHAIN_ELEMENT;
    pTrustListInfo: PCERT_TRUST_LIST_INFO;
  end;
  PCERT_SIMPLE_CHAIN = ^CERT_SIMPLE_CHAIN;
  PPCERT_SIMPLE_CHAIN= ^PCERT_SIMPLE_CHAIN;

  PCCERT_CHAIN_CONTEXT = ^CERT_CHAIN_CONTEXT;
  CERT_CHAIN_CONTEXT = record // 56 bytes
    cbSize     : DWORD;
    TrustStatus: CERT_TRUST_STATUS;
    cChain     : DWORD;
    rgpChain   : PPCERT_SIMPLE_CHAIN; // warning ! ^^CERT_SIMPLE_CHAIN
    // Following is returned when CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS
    // is set in dwFlags
    cLowerQualityChainContext: DWORD;
    rgpLowerQualityChainContext: ^PCCERT_CHAIN_CONTEXT;
    // fHasRevocationFreshnessTime is only set if we are able to retrieve
    // revocation information for all elements checked for revocation.
    // For a CRL its CurrentTime - ThisUpdate.
    //
    // dwRevocationFreshnessTime is the largest time across all elements
    // checked.
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime  : DWORD;
    // Flags passed when created via CertGetCertificateChain
    dwCreationFlags : DWORD;
    // Following is updated with unique Id when the chain context is logged.
    ChainId: TGUID;
  end;

  CERT_CHAIN_POLICY_PARA = record
    cbSize: DWORD;
    dwFlags: DWORD;
    pvExtraPolicyPara: Pointer;
  end;

  CERT_CHAIN_POLICY_STATUS = record
    cbSize: DWORD;
    dwError: HRESULT;
    lChainIndex: LONG;
    lElementIndex: LONG;
    pvExtraPolicyStatus: Pointer;
  end;

  CRL_ENTRY = record
    SerialNumber: CRYPT_INTEGER_BLOB;
    RevocationDate: FILETIME;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSION;
  end;
  PCRL_ENTRY = ^CRL_ENTRY;
  PPCRL_ENTRY = ^PCRL_ENTRY;

  CRL_INFO = record
    dwVersion: DWORD;
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    Issuer: CERT_NAME_BLOB;
    ThisUpdate: FILETIME;
    NextUpdate: FILETIME;
    cCRLEntry: DWORD;
    rgCRLEntry: PCRL_ENTRY;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSION;
  end;
  PCRL_INFO = ^CRL_INFO;

  CRL_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCrlEncoded: PBYTE;
    cbCrlEncoded: DWORD;
    pCrlInfo: PCRL_INFO;
    hCertStore: HCERTSTORE;
  end;
  PCRL_CONTEXT = ^CRL_CONTEXT;
  PCCRL_CONTEXT = PCRL_CONTEXT;

  HTTPSPolicyCallbackData = record
    //union {
    //cbStruct: DWORD;
      cbSize: DWORD;
    //};
    dwAuthType: DWORD;
    fdwChecks: DWORD;
    pwszServerName: PWCHAR;
  end;

  CERT_SERVER_OCSP_RESPONSE_CONTEXT = record
    cbSize: DWORD;
    pbEncodedOcspResponse: PBYTE;
    cbEncodedOcspResponse: DWORD;
  end;
  PCCERT_SERVER_OCSP_RESPONSE_CONTEXT = ^CERT_SERVER_OCSP_RESPONSE_CONTEXT;

  CRYPT_URL_INFO = record
    cbSize: DWORD;
    dwSyncDeltaTime: DWORD;
    cGroup: DWORD;
    rgcGroupEntry: PDWORD; // Array
  end;
  PCRYPT_URL_INFO = ^CRYPT_URL_INFO;

  CRYPT_URL_ARRAY = record
    cUrl: DWORD;
    rgwszUrl: PLPWSTR;
  end;
  PCRYPT_URL_ARRAY = ^CRYPT_URL_ARRAY;

  LPFILETIME = ^FILETIME;
  PCERT_REVOCATION_CRL_INFO = Pointer;
  PCERT_REVOCATION_CHAIN_PARA = Pointer;

  CERT_REVOCATION_PARA = record
    cbSize: DWORD;
    pIssuerCert: PCCERT_CONTEXT;
    cCertStore: DWORD;
    rgCertStore: PHCERTSTORE;
    hCrlStore: HCERTSTORE;
    pftTimeToUse: LPFILETIME;
    dwUrlRetrievalTimeout: DWORD;
    fCheckFreshnessTime: BOOL;
    dwFreshnessTime: DWORD;
    pftCurrentTime: LPFILETIME;
    pCrlInfo: PCERT_REVOCATION_CRL_INFO;
    pftCacheResync: LPFILETIME;
    pChainPara: PCERT_REVOCATION_CHAIN_PARA;
  end;
  PCERT_REVOCATION_PARA = ^CERT_REVOCATION_PARA;

  CERT_REVOCATION_STATUS = record
    cbSize: DWORD;
    dwIndex: DWORD;
    dwError: DWORD;
    dwReason: DWORD;
    fHasFreshnessTime: BOOL;
    dwFreshnessTime: DWORD;
  end;
  PCERT_REVOCATION_STATUS = ^CERT_REVOCATION_STATUS;

  CERT_CONTEXT_HELPER = record helper for CERT_CONTEXT
    function FindExtension(OID: PAnsiChar): PCERT_EXTENSION;
  end;

function PFXImportCertStore(
  pPFX: PCRYPT_DATA_BLOB;
  szPassword: LPCWSTR;
  dwFlags: DWORD
): HCERTSTORE; stdcall; external CRYPT32;

function CertCreateCertificateContext(
  dwCertEncodingType: DWORD;
  pbCertEncoded: Pointer;
  cbCertEncoded: DWORD
): PCCERT_CONTEXT; stdcall; external CRYPT32;

function CertFreeCertificateContext(
  pCertContext :PCCERT_CONTEXT
):BOOL; stdcall; external CRYPT32;

function CertGetCertificateChain (
       hChainEngine: HCERTCHAINENGINE;
       pCertContext: PCCERT_CONTEXT;
       pTime: PFILETIME;
       hAdditionalStore: HCERTSTORE;
 const pChainPara: CERT_CHAIN_PARA;
       dwFlags: DWORD;
       pvReserved: LPVOID;
  var  ppChainContext: PCCERT_CHAIN_CONTEXT
): BOOL; stdcall; external CRYPT32;

function CertVerifyCertificateChainPolicy(
        pszPolicyOID: LPCSTR;
        pChainContext: PCCERT_CHAIN_CONTEXT;
  const pPolicyPara: CERT_CHAIN_POLICY_PARA;
  const pPolicyStatus: CERT_CHAIN_POLICY_STATUS
): BOOL; stdcall; external CRYPT32;

function CertVerifyRevocation(
       dwEncodingType: DWORD;
       dwRevType: DWORD;
       cContext: DWORD;
 const rgpvContext: TArray<PCCERT_CONTEXT>;
       dwFlags: DWORD;
       pRevPara: PCERT_REVOCATION_PARA;
       pRevStatus: PCERT_REVOCATION_STATUS
): BOOL; stdcall; external CRYPT32;

function CertGetCertificateContextProperty(
      pCertContext: PCCERT_CONTEXT;
      dwPropId: DWORD;
      pvData: Pointer;
  var pcbData: DWORD
): BOOL; stdcall; external CRYPT32;

function CertFindExtension(
  pszObjId    : PAnsiChar;
  cExtensions : DWORD;
  rgExtensions: PCERT_EXTENSION
): PCERT_EXTENSION; stdcall; external CRYPT32;

function CertOpenServerOcspResponse(
  pChainContext: PCCERT_CHAIN_CONTEXT;
  dwFlags: DWORD;
  pOpenPara: Pointer // PCERT_SERVER_OCSP_RESPONSE_OPEN_PARA
): HCERT_SERVER_OCSP_RESPONSE; stdcall; external CRYPT32;

procedure CertCloseServerOcspResponse(
  hServerOcspResponse: HCERT_SERVER_OCSP_RESPONSE ;
  dwFlags: DWORD
); stdcall; external CRYPT32;

function CertGetServerOcspResponseContext(
  hServerOcspResponse: HCERT_SERVER_OCSP_RESPONSE;
  dwFlags: DWORD;
  pvRserved: LPVOID
): PCCERT_SERVER_OCSP_RESPONSE_CONTEXT; stdcall; external CRYPT32;

procedure CertFreeServerOcspResponseContext(
  pServerOcspResponseContext: PCCERT_SERVER_OCSP_RESPONSE_CONTEXT
); stdcall; external CRYPT32;

function CertFreeCertificateChain (
  pChainContext: PCCERT_CHAIN_CONTEXT
): BOOL; stdcall; external CRYPT32;

function CryptEncryptMessage(
  const pEncryptPara: CRYPT_ENCRYPT_MESSAGE_PARA;
        cRecipientCert: DWORD;
        rgpRecipientCert: PPCCERT_CONTEXT;
        pbToBeEncrypted: Pointer;
        cbToBeEncrypted: DWORD;
        pbEncryptedBlob: Pointer;
    var pcbEncryptedBlob: DWORD
): BOOL; stdcall; external CRYPT32;

function CertNameToStr(
        dwCertEncodingType: DWORD;
  const pName: CERT_NAME_BLOB;
        dwStrType: DWORD;
        psz: PChar;
        csz: DWORD
):DWORD ; stdcall; external CRYPT32 name 'CertNameToStrW';

function CryptDecodeObjectEx(
  dwCertEncodingType: DWORD;
  lpszStructType: LPCSTR;
  pbEncoded: PBYTE;
  cbEncoded: DWORD;
  dwFlags: DWORD;
  pDecodePara: PCRYPT_DECODE_PARA;
  pvStructInfo: Pointer;
  pcbStructInfo: PDWORD
): BOOL; stdcall; external CRYPT32;

function CryptGetObjectUrl(
  pszUrlOid: LPCSTR;
  pvPara: LPVOID;
  dwFlags: DWORD;
  pUrlArray: PCRYPT_URL_ARRAY;
  pcbUrlArray: PDWORD;
  pUrlInfo: PCRYPT_URL_INFO;
  pcbUrlInfo: PDWORD;
  lpReserved: LPVOID
): BOOL; stdcall external 'Cryptnet.dll';

// Cryptography API: Next Generation
//-----------------------------------
// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal

const
  BCRYPT = 'Bcrypt.dll';

  MS_PRIMITIVE_PROVIDER = 'Microsoft Primitive Provider';

  BCRYPT_RNG_ALGORITHM = 'RNG';
  BCRYPT_RSA_ALGORITHM = 'RSA';
  BCRYPT_AES_ALGORITHM = 'AES';
  BCRYPT_ECDH_ALGORITHM = 'ECDH';
  BCRYPT_ECDH_P256_ALGORITHM = 'ECDH_P256'; //  secp256r1
  BCRYPT_ECDH_P384_ALGORITHM = 'ECDH_P384'; //  secp384r1

  BCRYPT_CHAINING_MODE = 'ChainingMode';
  BCRYPT_CHAIN_MODE_CBC : string = 'ChainingModeCBC';
  BCRYPT_CHAIN_MODE_GCM : string = 'ChainingModeGCM';
  BCRYPT_AUTH_TAG_LENGTH = 'AuthTagLength';
  BCRYPT_BLOCK_LENGTH = 'BlockLength';

  BCRYPT_ECC_CURVE_NAME = 'ECCCurveName';
  BCRYPT_ECC_CURVE_25519 : string = 'curve25519';
  BCRYPT_ECC_CURVE_SECP256R1: string = 'secP256r1';

  BCRYPT_ECCPRIVATE_BLOB = 'ECCPRIVATEBLOB';
  BCRYPT_ECCPUBLIC_BLOB = 'ECCPUBLICBLOB';
  BCRYPT_RSAPUBLIC_BLOB = 'RSAPUBLICBLOB';
  BCRYPT_RSAPRIVATE_BLOB = 'RSAPRIVATEBLOB';
  BCRYPT_RSAFULLPRIVATE_BLOB = 'RSAFULLPRIVATEBLOB';
  BCRYPT_KEY_DATA_BLOB = 'KeyDataBlob';
  LEGACY_RSAPRIVATE_BLOB = 'CAPIPRIVATEBLOB';

  BCRYPT_KDF_RAW_SECRET = 'TRUNCATE';

  BCRYPT_BLOCK_PADDING = 1;

  BCRYPT_PAD_NONE  = 1;
  BCRYPT_PAD_PKCS1 = 2;

  BCRYPT_RNG_USE_ENTROPY_IN_BUFFER = 1;
  BCRYPT_USE_SYSTEM_PREFERRED_RNG  = 2;

  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;

  CERT_STORE_PROV_MSG = LPCSTR(1);
  CERT_STORE_PROV_MEMORY = LPCSTR(2);
  CERT_STORE_PROV_FILE = LPCSTR(3);
  CERT_STORE_PROV_REG = LPCSTR(4);
  CERT_STORE_PROV_PKCS7 = LPCSTR(5);
  CERT_STORE_PROV_SERIALIZED = LPCSTR(6);
  CERT_STORE_PROV_FILENAME_A = LPCSTR(7);
  CERT_STORE_PROV_FILENAME_W = LPCSTR(8);
  CERT_STORE_PROV_SYSTEM_A = LPCSTR(9);
  CERT_STORE_PROV_SYSTEM_W = LPCSTR(10);

  CERT_STORE_NO_CRYPT_RELEASE_FLAG            = $00000001;
  CERT_STORE_SET_LOCALIZED_NAME_FLAG          = $00000002;
  CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG = $00000004;
  CERT_STORE_DELETE_FLAG                      = $00000010;
  CERT_STORE_MANIFOLD_FLAG                    = $00000100;
  CERT_STORE_ENUM_ARCHIVED_FLAG               = $00000200;
  CERT_STORE_UPDATE_KEYID_FLAG                = $00000400;
  CERT_STORE_READONLY_FLAG                    = $00008000;
  CERT_STORE_OPEN_EXISTING_FLAG               = $00004000;
  CERT_STORE_CREATE_NEW_FLAG                  = $00002000;
  CERT_STORE_MAXIMUM_ALLOWED_FLAG             = $00001000;

  CERT_STORE_SIGNATURE_FLAG     = $00001;
  CERT_STORE_TIME_VALIDITY_FLAG = $00002;
  CERT_STORE_REVOCATION_FLAG    = $00004;
  CERT_STORE_NO_CRL_FLAG        = $10000;
  CERT_STORE_NO_ISSUER_FLAG     = $20000;

  // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  // https://davidvielmetter.com/tips/ntstatus-error-code-list/comment-page-1/
  STATUS_INVALID_PARAMETER   = $C000000D;
  STATUS_BUFFER_TOO_SMALL    = $C0000023;
  STATUS_NOT_SUPPORTED       = $C00000BB;
  STATUS_INVALID_BUFFER_SIZE = $C0000206;
  STATUS_AUTH_TAG_MISMATCH   = $C000A002;
  STATUS_INVALID_SIGNATURE   = $C000A000;

  BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = $504B4345;
  BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = $564B4345;
  BCRYPT_RSAPUBLIC_MAGIC  = $31415352;  // RSA1
  BCRYPT_RSAPRIVATE_MAGIC = $32415352;  // RSA2
  BCRYPT_RSAFULLPRIVATE_MAGIC = $33415352; // RSA3

  CERT_STORE_ADD_NEW                                  = 1;
  CERT_STORE_ADD_USE_EXISTING                         = 2;
  CERT_STORE_ADD_REPLACE_EXISTING                     = 3;
  CERT_STORE_ADD_ALWAYS                               = 4;
  CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES  = 5;
  CERT_STORE_ADD_NEWER                                = 6;
  CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES             = 7;

type
  BCRYPT_HANDLE     = THandle;
  BCRYPT_ALG_HANDLE = THandle;


  BCRYPT_PKCS1_PADDING_INFO = record
    psaAligId: LPCWSTR; // BCRYPT_SHA256_ALGORITHM
  end;
  PBCRYPT_PKCS1_PADDING_INFO = ^BCRYPT_PKCS1_PADDING_INFO;

  BCRYPT_AUTH_TAG_LENGTHS_STRUCT = record
    dwMinLength: ULONG;
    dwMaxLength: ULONG;
    dwIncrement: ULONG;
  end;

  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO = record
    cbSize: ULONG;
    dwInfoVersion: ULONG;
    pbNonce: PUCHAR;
    cbNonce: ULONG;
    pbAuthData: PUCHAR;
    cbAuthData: ULONG;
    pbTag: PUCHAR;
    cbTag: ULONG;
    pbMacContext: PUCHAR;
    cbMacContext: ULONG;
    cbAAD: ULONG;
    cbData: ULONGLONG;
    cwFlags: ULONG;
  end;

  BCRYPT_ECCKEY_BLOB = packed record
    dwMagic: ULONG;
    cbKey  : ULONG;
  //X: array[cbKey] of Byte
  //Y: array[cbKey] of Byte
  //d: array[cbKey] of Byte (for private key only)
  end;
  PBCRYPT_ECCKEY_BLOB = ^BCRYPT_ECCKEY_BLOB;

  BCRYPT_KEY_DATA_BLOB_HEADER = packed record
    dwMagic: ULONG;
    dwVersion: ULONG;
    cbKeyData: ULONG;
  end;
  PBCRYPT_KEY_DATA_BLOB_HEADER = ^BCRYPT_KEY_DATA_BLOB_HEADER;

  BCRYPT_RSAKEY_BLOB = packed record
    Magic: ULONG;
    BitLength: ULONG;
    cbPublicExp: ULONG;
    cbModulus: ULONG;
    cbPrime1: ULONG;
    cbPrime2: ULONG;
  end;
  PBCRYPT_RSAKEY_BLOB = ^BCRYPT_RSAKEY_BLOB;

procedure BCRYPT_INIT_AUTH_MODE_INFO(var Value: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);

function CertOpenStore(
  lpszStoreProvider: LPCSTR;
  dwEncodingType: DWORD;
  hCryptProv: Pointer;//HCRYPTPROV_LEGACY;
  dwFlags: DWORD;
  pvPara: Pointer
): HCERTSTORE; stdcall; external CRYPT32;

function CertEnumCertificatesInStore(
  hCertStore: HCERTSTORE;
  pPrevCertContext: PCCERT_CONTEXT
): PCCERT_CONTEXT; stdcall; external CRYPT32;

function CertEnumCTLsInStore(
  hCertStore: HCERTSTORE;
  pPrevCrlContext: PCCTL_CONTEXT
): PCCTL_CONTEXT; stdcall; external CRYPT32;

function CertGetIssuerCertificateFromStore(
  hCertStore: HCERTSTORE;
  pSubjectContext: PCCERT_CONTEXT;
  pPrevIssuerContext: PCCERT_CONTEXT;
  pdwFlags: PDWORD
): PCCERT_CONTEXT; stdcall; external CRYPT32;

function CertAddCertificateContextToStore(
  hCertStore: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  dwAddDisposition: DWORD;
  ppStoreContext: PPCCERT_CONTEXT
): BOOL; stdcall; external CRYPT32;

function CertDuplicateCertificateContext(
  pCertContext: PCCERT_CONTEXT
):PCCERT_CONTEXT; stdcall; external CRYPT32;

function CertAddEncodedCRLToStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  pbCrlEncoded: Pointer;
  cbCrlEncoded: DWORD;
  dwAddDisposition: DWORD
): BOOL; stdcall; external CRYPT32;

function CertGetCRLFromStore(
      hCertStore: HCERTSTORE;
      pIssuercontext: PCCERT_CONTEXT;
      pPrevCrlContext: PCCRL_CONTEXT;
  var pdwFlags: DWORD
): PCCRL_CONTEXT; stdcall; external CRYPT32;

function CertCreateCRLContext(
  dwCertEncodingType: DWORD;
  pbCrlEncoded: PBYTE;
  cbCrlEncoded: DWORD
): PCCRL_CONTEXT; stdcall; external CRYPT32;

function CertFreeCRLContext(
  pCrlContext: PCCRL_CONTEXT
): BOOL; stdcall; external CRYPT32;

function CertFindCertificateInCRL(
      pCert: PCCERT_CONTEXT;
      pCrlContext: PCCRL_CONTEXT;
      dwFlags: DWORD;
      pvReserved: Pointer;
  var ppCrlEntry: PCRL_ENTRY
): BOOL; stdcall; external CRYPT32;

function CryptImportPublicKeyInfoEx2(
      dwCertEncodingType: DWORD;     // X509_ASN_ENCODING
      pInfo: PCERT_PUBLIC_KEY_INFO;
      dwFlags: DWORD;
      pvAuxInfo: Pointer;            // nil
  var phKey: BCRYPT_KEY_HANDLE
): BOOL; stdcall; external CRYPT32;

function BCryptDestroyKey(
  hKey: BCRYPT_KEY_HANDLE
): NTSTATUS; stdcall external BCRYPT;

function BCryptOpenAlgorithmProvider(
    var phAlgorithm: BCRYPT_ALG_HANDLE;
  const pszAlgId: string;
        pszImplementation: PChar;
        dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptCloseAlgorithmProvider(
        hAlgorithm: BCRYPT_ALG_HANDLE;
        dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptSetProperty(
  hObject: BCRYPT_HANDLE;
  pszProperty: LPCWSTR;
  pbInput: PUCHAR;
  cbInput: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptGetProperty(
  hObject: BCRYPT_HANDLE;
  pszProperty: LPCWSTR;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  pcbResult: PULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptGenerateSymmetricKey(
      hAlgorithm: BCRYPT_ALG_HANDLE;
  var phKey: BCRYPT_KEY_HANDLE;
      pbKeyObject: PUCHAR;
      cbKeyObject: ULONG;
      pbSecret: PUCHAR;
      cbSecret: ULONG;
      dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptGenerateKeyPair(
      hAlgorithm: BCRYPT_ALG_HANDLE;
  var phKey: BCRYPT_KEY_HANDLE;
      dwLength: ULONG;
      dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptFinalizeKeyPair(
  hKey: BCRYPT_KEY_HANDLE;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptImportKey(
     hAlgorithm: BCRYPT_ALG_HANDLE;
     hImportKey: BCRYPT_KEY_HANDLE;  // not used
     pszBlobType: LPCWSTR;
 var phKey: BCRYPT_KEY_HANDLE;
     pbKeyObject: PUCHAR;
     cbKeyOjject: ULONG;
     pbInput: PUCHAR;
     cbInput: ULONG;
     dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptImportKeyPair(
     hAlgorithm: BCRYPT_ALG_HANDLE;
     hImportKey: BCRYPT_KEY_HANDLE;  // not used
     pszBlobType: LPCWSTR;
 var phKey: BCRYPT_KEY_HANDLE;
     pbInput: PUCHAR;
     cbInput: ULONG;
     dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptExportKey(
  hKey: BCRYPT_KEY_HANDLE;
  hExportKey: BCRYPT_KEY_HANDLE;
  pszBlobType: LPCWSTR;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  pcbResult: PULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptGenRandom(
        hAlgorithm: BCRYPT_ALG_HANDLE;
    var pbBuffer;
        cbVuffer: ULONG;
        dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptEncrypt(
  hKey: BCRYPT_KEY_HANDLE;
  pbInput: PUCHAR;
  cbInput: ULONG;
  pPaddingInfo: Pointer;
  pbIV: PUCHAR;
  cbIV: ULONG;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  pcbResult: PULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptDecrypt(
  hKey: BCRYPT_KEY_HANDLE;
  pbInput: PUCHAR;
  cbInput: ULONG;
  pPaddingInfo: Pointer;
  pbIV: PUCHAR;
  cbIV: ULONG;
  pbOutput: PUCHAR;
  cbOutput: ULONG;
  pcbResult: PULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptSignHash(
  hKey: BCRYPT_KEY_HANDLE;
  pPaddingInfo: PBCRYPT_PKCS1_PADDING_INFO;
  pbInput: Pointer;
  cbInput: ULONG;
  pbOutput: Pointer;
  cbOutput: ULONG;
  pcbResult: PULONG;
  dwFlags: ULONG  // BCRYPT_PAD_PKCS1
): NTSTATUS; stdcall external BCRYPT;

function BCryptVerifySignature(
  hKey: BCRYPT_KEY_HANDLE;
  pPaddingInfo: PBCRYPT_PKCS1_PADDING_INFO;
  pbHash: PUCHAR;
  cbHash: ULONG;
  pbSignature: PUCHAR;
  cbSignature: ULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptSecretAgreement(
      hPrivKey: BCRYPT_KEY_HANDLE;
      hPubKey: BCRYPT_KEY_HANDLE;
  var phAgreedSecret: BCRYPT_SECRET_HANDLE ;
      dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptDeriveKey(
  hSharedSecret: BCRYPT_SECRET_HANDLE;
  pwszKDF: LPCWSTR;
  pParameterList: Pointer;
  pbDerivedKey: PUCHAR;
  cbDerivedKey: ULONG;
  pcbResult: PULONG;
  dwFlags: ULONG
): NTSTATUS; stdcall external BCRYPT;

function BCryptDestroySecret(
  hSecret: BCRYPT_SECRET_HANDLE
): NTSTATUS; stdcall external BCRYPT;

const
  PROV_RSA_FULL = $01;
  PROV_RSA_AES  = $18;
  CRYPT_VERIFYCONTEXT = $F0000000;

function CryptAcquireContext(
  var phProv: HCRYPTPROV;
  szContainer: LPCSTR;
  szProvider: LPCSTR;
  dwProvType: DWORD;
  dwFlags: DWORD
): BOOL; stdcall; external ADVAPI32 name 'CryptAcquireContextA';

function CryptImportPublicKeyInfo(
      hCryptProv: HCRYPTPROV;
      dwCertEncodingType: DWORD;
      pInfo: PCERT_PUBLIC_KEY_INFO;
  var phKey: HCRYPTKEY
): BOOL; stdcall; external CRYPT32;

function CryptEncrypt(
      hKey: HCRYPTKEY;
      hHash: HCRYPTHASH;
      Final: BOOL;
      dwFlags: DWORD;
      pbData: PByte;
  var pbwDataLen: DWORD;
      dwBufLen: DWORD
): BOOL; stdcall; external ADVAPI32;


function NTSTATUSText(Status: NTSTATUS): string;
procedure NTSTATUSCheck(Status: NTSTATUS);

function CertName(Cert: PCCERT_CONTEXT; var Blob: CERT_NAME_BLOB; Flags: DWORD = CERT_X500_NAME_STR or CERT_NAME_STR_NO_PLUS_FLAG or CERT_NAME_STR_REVERSE_FLAG): string;
function SerialNumber(const Number: CRYPT_INTEGER_BLOB): string;

function CertIssuerFlags(dwFlags: DWORD): string;

procedure FillRandom(var Data; Count: Integer);

implementation

procedure FillRandom(var Data; Count: Integer);
begin
  BCryptGenRandom(0, Data, Count, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
end;

const
  CERT_TRUST_CODES: array[0..23] of Cardinal =(
    CERT_TRUST_IS_NOT_TIME_VALID,
    CERT_TRUST_IS_REVOKED,
    CERT_TRUST_IS_NOT_SIGNATURE_VALID,
    CERT_TRUST_IS_NOT_VALID_FOR_USAGE,
    CERT_TRUST_IS_UNTRUSTED_ROOT,
    CERT_TRUST_REVOCATION_STATUS_UNKNOWN,
    CERT_TRUST_IS_CYCLIC,
    CERT_TRUST_INVALID_EXTENSION,
    CERT_TRUST_INVALID_POLICY_CONSTRAINTS,
    CERT_TRUST_INVALID_BASIC_CONSTRAINTS,
    CERT_TRUST_INVALID_NAME_CONSTRAINTS,
    CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT,
    CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT,
    CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT,
    CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT,
    CERT_TRUST_IS_OFFLINE_REVOCATION,
    CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY,
    CERT_TRUST_IS_EXPLICIT_DISTRUST,
    CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT,
    CERT_TRUST_HAS_WEAK_SIGNATURE,
    CERT_TRUST_IS_PARTIAL_CHAIN,
    CERT_TRUST_CTL_IS_NOT_TIME_VALID,
    CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID,
    CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE
  );
  CERT_TRUST_NAMES: array[0..23] of string = (
    'CERT_TRUST_IS_NOT_TIME_VALID',
    'CERT_TRUST_IS_REVOKED',
    'CERT_TRUST_IS_NOT_SIGNATURE_VALID',
    'CERT_TRUST_IS_NOT_VALID_FOR_USAGE',
    'CERT_TRUST_IS_UNTRUSTED_ROOT',
    'CERT_TRUST_REVOCATION_STATUS_UNKNOWN',
    'CERT_TRUST_IS_CYCLIC',
    'CERT_TRUST_INVALID_EXTENSION',
    'CERT_TRUST_INVALID_POLICY_CONSTRAINTS',
    'CERT_TRUST_INVALID_BASIC_CONSTRAINTS',
    'CERT_TRUST_INVALID_NAME_CONSTRAINTS',
    'CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT',
    'CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT',
    'CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT',
    'CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT',
    'CERT_TRUST_IS_OFFLINE_REVOCATION',
    'CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY',
    'CERT_TRUST_IS_EXPLICIT_DISTRUST',
    'CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT',
    'CERT_TRUST_HAS_WEAK_SIGNATURE',
    'CERT_TRUST_IS_PARTIAL_CHAIN',
    'CERT_TRUST_CTL_IS_NOT_TIME_VALID',
    'CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID',
    'CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE'
  );

function CertTrusts(Flags: DWORD): string;
begin
  Result := '';
  if Flags = 0 then
    Result := 'CERT_TRUST_NO_ERROR'
  else begin
    for var i := Low(CERT_TRUST_CODES) to High(CERT_TRUST_CODES) do
    begin
      if (Flags and CERT_TRUST_CODES[I]) = CERT_TRUST_CODES[I] then
      begin
        Result := Result + ',' + CERT_TRUST_NAMES[I];
        Dec(Flags, CERT_TRUST_CODES[I]);
      end;
    end;
    if Flags <> 0 then
      Result := Result + ',0x' + IntToHex(Flags);
    Result[1] := '[';
    Result := Result + ']';
  end;
end;

const
  ISSUER_FLAGS_CODE : array[0..4] of DWORD = (
    CERT_STORE_SIGNATURE_FLAG,
    CERT_STORE_TIME_VALIDITY_FLAG,
    CERT_STORE_REVOCATION_FLAG,
    CERT_STORE_NO_CRL_FLAG,
    CERT_STORE_NO_ISSUER_FLAG
  );
  ISSUER_FLAGS_NAME: array[0..4] of string = (
    'CERT_STORE_SIGNATURE_FLAG',
    'CERT_STORE_TIME_VALIDITY_FLAG',
    'CERT_STORE_REVOCATION_FLAG',
    'CERT_STORE_NO_CRL_FLAG',
    'CERT_STORE_NO_ISSUER_FLAG'
  );

function CertIssuerFlags(dwFlags: DWORD): string;
begin
  Result := '';
  if dwFlags <> 0 then
  begin
    for var i := Low(ISSUER_FLAGS_CODE) to High(ISSUER_FLAGS_CODE) do
    begin
      if (dwFlags and ISSUER_FLAGS_CODE[I]) = ISSUER_FLAGS_CODE[I] then
      begin
        Result := Result + ',' + ISSUER_FLAGS_NAME[I];
        Dec(dwFlags, ISSUER_FLAGS_CODE[I]);
      end;
    end;
    if dwFlags <> 0 then
      Result := Result + ',0x' + IntToHex(dwFlags);
    Result[1] := '[';
    Result := Result + ']';
  end;
end;

procedure BCRYPT_INIT_AUTH_MODE_INFO(var Value: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
begin
  FillChar(Value, SizeOf(Value), 0);
  Value.cbSize := SizeOf(Value);
  Value.dwInfoVersion := BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
end;

function NTSTATUSText(Status: NTSTATUS): string;
begin
  case ULONG(Status) of
    0 : Result := '';
    STATUS_INVALID_HANDLE   : Result := 'STATUS_INVALID_HANDLE';
    STATUS_INVALID_PARAMETER: Result := 'STATUS_INVALID_PARAMETER';
    STATUS_BUFFER_TOO_SMALL : Result := 'STATUS_BUFFER_TOO_SMALL';
    STATUS_AUTH_TAG_MISMATCH : Result := 'STATUS_AUTH_TAG_MISMATCH ';
    STATUS_NOT_SUPPORTED : Result := 'STATUS_NOT_SUPPORTED';
    STATUS_INVALID_BUFFER_SIZE : Result := 'STATUS_INVALID_BUFFER_SIZE';
  else
    Result := 'NTSTATUS ' + IntToHex(Status);
  end;
end;
procedure NTSTATUSCheck(Status: NTSTATUS);
begin
  if Status <> 0 then
    raise Exception.Create(NTSTATUSText(Status));
end;

function CertName(Cert: PCCERT_CONTEXT; var Blob: CERT_NAME_BLOB; Flags: DWORD = CERT_X500_NAME_STR or CERT_NAME_STR_NO_PLUS_FLAG or CERT_NAME_STR_REVERSE_FLAG): string;
var
  Len: Integer;
begin
  Len := CertNameToStr(Cert.dwCertEncodingType, Blob, Flags, nil, 0);
  if Len <= 1 then
    Exit('');
  SetLength(Result, Len - 1); // string has already an extra #0
  CertNameToStr(Cert.dwCertEncodingType, Blob, Flags, @Result[1], Len + 1);
end;

function SerialNumber(const Number: CRYPT_INTEGER_BLOB): string;
// FF00 -> 255,0  => 65280
// 1980 -> 25,128 -> 0
// 028C ->  2,140 -> 8
// 0041 ->  0, 65 -> 2
// 0006 ->  0,  6 -> 5
// 0000 ->      0 -> 6
var
  Index : Integer;
  Value : Integer;
  Digits: Integer;
  Bytes : TArray<Byte>;
begin
  Digits := Number.cbData;
  SetLength(Bytes, Digits);
    Move(Number.pbData^, Bytes[0], Digits);
  Result := '';
  Dec(Digits);
  while Digits >= 0 do
  begin
    Value := 0;
    for Index := Digits downto 0 do
    begin
      Value := Value * 256 + Bytes[Index];
      Bytes[Index] := Value div 10;
      Value := Value mod 10;
    end;
    Result := Char(Ord('0') + Value) + Result;
    if Bytes[Digits] = 0 then
      Dec(Digits);
  end;
end;

{ CERT_CONTEXT_HELPER }

function CERT_CONTEXT_HELPER.FindExtension(OID: PAnsiChar): PCERT_EXTENSION;
begin
  Result := CertFindExtension(OID, pCertInfo.cExtension, pCertInfo.rgExtension);
end;

end.


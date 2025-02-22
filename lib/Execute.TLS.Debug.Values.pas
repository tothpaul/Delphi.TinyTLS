unit Execute.TLS.Debug.Values;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface
{$TYPEINFO OFF}
uses
  System.SysUtils,
  Execute.TinyTLS.Types,
  Execute.TinyTLS.Extensions,
  Execute.TinyTLS.Fragments;

function GetContentType(Value: TContentType): string;
function GetHandshakeType(Value: THandshakeType): string;
function GetProtocolVersion(const Version: TProtocolVersion): string;
function GetCipherSuite(Value: TCipherSuiteTag): string;
function GetCompressionMethod(Value: TCompressionMethodTag): string;
function GetExtensionType(Value: TExtensionType): string;
function GetHashAlgorithm(Value: THashAlgorithm): string;
function GetSignatureAlgorithm(Value: TSignatureAlgorithm): string;
function GetSignatureScheme(Value: TSignatureScheme): string;
function GetSignatureAndHashAlgorithm(const Value: TSignatureAndHashAlgorithm): string;
function GetSupportedGroup(Value: TSupportedGroup): string;
function GetECPointFormat(Value: TECPointFormat): string;
//function GetSignatureScheme(Value: TSignatureScheme): string;
function GetCurveType(Value: TCurveType): string;
function GetAlertLevel(Value: TAlertLevel): string;
function GetAlertDescription(Value: TAlertDescription): string;
function GetClientCertificateType(Value: TClientCertificateType): string;

implementation

function GetContentType(Value: TContentType): string;
begin
  case Value of
    ChangeCipherSpec: Result := 'ChangeCipherSpec';
    Alert: Result := 'Alert';
    HandShake: Result := 'HandShake';
    ApplicationData: Result := 'ApplicationData';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetHandshakeType(Value: THandshakeType): string;
begin
  case Value of
    HelloRequest: Result := 'HelloRequest';
    ClientHello: Result := 'ClientHello';
    ServerHello: Result := 'ServerHello';
    NewSessionTicket: Result := 'NewSessionTicket';
    Certificate: Result := 'Certificate';
    ServerKeyExchange: Result := 'ServerKeyExchange';
    CertificateRequest: Result := 'CertificateRequest';
    ServerHelloDone: Result := 'ServerHelloDone';
    CertificateVerify: Result := 'CertificateVerify';
    ClientKeyExchange: Result := 'ClientKeyExchange';
    Finished: Result := 'Finished';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetProtocolVersion(const Version: TProtocolVersion): string;
begin
  Result := '0x' + IntToHex(Swap(Word(Version))) + ' : {major: ' + IntToStr(Version.major) + ', minor: ' + IntToStr(Version.minor) + '}';
  if (Version.major = 3) then
  case Version.minor of
    1: Result := Result + ' // TLS 1.0';
    2: Result := Result + ' // TLS 1.1';
    3: Result := Result + ' // TLS 1.2';
    4: Result := Result + ' // TLS 1.3';
  end;
end;

function GetCipherSuite(Value: TCipherSuiteTag): string;
begin
  case Value of
    TLS_RSA_WITH_RC4_128_MD5: Result := 'TLS_RSA_WITH_RC4_128_MD5';
    TLS_RSA_WITH_RC4_128_SHA: Result := 'TLS_RSA_WITH_RC4_128_SHA';
    TLS_RSA_WITH_3DES_EDE_CBC_SHA: Result := 'TLS_RSA_WITH_3DES_EDE_CBC_SHA';
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: Result := 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA';
    TLS_RSA_WITH_AES_128_CBC_SHA: Result := 'TLS_RSA_WITH_AES_128_CBC_SHA';
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA: Result := 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA';
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA: Result := 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA';
    TLS_RSA_WITH_AES_256_CBC_SHA: Result := 'TLS_RSA_WITH_AES_256_CBC_SHA';
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA: Result := 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA';
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA: Result := 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA';
    TLS_RSA_WITH_AES_128_CBC_SHA256: Result := 'TLS_RSA_WITH_AES_128_CBC_SHA256';
    TLS_RSA_WITH_AES_256_CBC_SHA256: Result := 'TLS_RSA_WITH_AES_256_CBC_SHA256';
    TLS_RSA_WITH_AES_128_GCM_SHA256: Result := 'TLS_RSA_WITH_AES_128_GCM_SHA256';
    TLS_RSA_WITH_AES_256_GCM_SHA384: Result := 'TLS_RSA_WITH_AES_256_GCM_SHA384';
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: Result := 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256';
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: Result := 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384';
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV: Result := 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV';
    TLS_AES_128_GCM_SHA256: Result := 'TLS_AES_128_GCM_SHA256';
    TLS_AES_256_GCM_SHA384: Result := 'TLS_AES_256_GCM_SHA384';
    TLS_CHACHA20_POLY1305_SHA256: Result := 'TLS_CHACHA20_POLY1305_SHA256';
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA';
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA';
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Result := 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA';
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Result := 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA';
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Result := 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256';
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Result := 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: Result := 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384';
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Result := 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384';
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384';
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256';
  else
    Result := '';
  end;
  Result := Result + ' (0x' + IntToHex(Ord(Value)) + ')';
end;

function GetCompressionMethod(Value: TCompressionMethodTag): string;
begin
  case Value of
    Null: Result := 'Null';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetExtensionType(Value: TExtensionType): string;
begin
  case Value of
    ServerName: Result := 'ServerName';
    SupportedGroups: Result := 'SupportedGroups';
    ECPointFormats: Result := 'ECPointFormats';
    EncryptThenMac: Result := 'EncryptThenMac';
    ExtendedMasterSecret: Result := 'ExtendedMasterSecret';
    SessionTicketTLS: Result := 'SessionTicketTLS';
    SupportedVersions: Result := 'SupportedVersions';
    PSKeyExchangeModes: Result := 'PSKeyExchangeModes';
    RenegotiationInfo: Result := 'RenegotiationInfo';
    SignatureAlgorithms: Result := 'SignatureAlgorithms';
    PostHandshakeAuth: Result := 'PostHandshakeAuth';
    KeyShare: Result := 'KeyShare';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetHashAlgorithm(Value: THashAlgorithm): string;
begin
  case Value of
    none: Result := 'none';
    md5: Result := 'md5';
    sha1: Result := 'sha1';
    sha224: Result := 'sha224';
    sha256: Result := 'sha256';
    sha384: Result := 'sha384';
    sha512: Result := 'sha512';
    Intrinsic: Result := 'Intrinsic';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetSignatureAlgorithm(Value: TSignatureAlgorithm): string;
begin
  case Value of
    anonymous: Result := 'anonymous';
    rsa: Result := 'rsa';
    dsa: Result := 'dsa';
    ecdsa: Result := 'ecdsa';
    ed25519_: Result := 'ed25519';
    ed448_: Result := 'ed448';
    gostr34102012_256: Result := 'gostr34102012_256';
    gostr34102012_512: Result := 'gostr34102012_512';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetSignatureScheme(Value: TSignatureScheme): string;
begin
  case Value of
    rsa_pkcs1_sha1: Result := 'rsa_pkcs1_sha1';
    TLS12_dsa_sha1: Result := 'TLS12_dsa_sha1';
    ecdsa_sha1: Result := 'ecdsa_sha1';
    rsa_pkcs1_sha256: Result := 'rsa_pkcs1_sha256';
    TLS12_dsa_sha256: Result := 'TLS12_dsa_sha256';
    rsa_pkcs1_sha384: Result := 'rsa_pkcs1_sha384';
    TLS12_dsa_sha384: Result := 'TLS12_dsa_sha384';
    rsa_pkcs1_sha512: Result := 'rsa_pkcs1_sha512';
    ecdsa_secp254r1_sha256: Result := 'ecdsa_secp254r1_sha256';
    ecdsa_secp384r1_sha384: Result := 'ecdsa_secp384r1_sha384';
    TLS12_dsa_sha512: Result := 'TLS12_dsa_sha512';
    ecdsa_secp521r1_sha512: Result := 'ecdsa_secp521r1_sha512';
    rsa_pss_sha256: Result := 'rsa_pss_sha256';
    rsa_pss_sha384: Result := 'rsa_pss_sha384';
    rsa_pss_sha512: Result := 'rsa_pss_sha512';
    TLS13_ed25519: Result := 'TLS13_ed25519';
    TLS13_ed448: Result := 'TLS13_ed448';
    rsa_pss_rsae_sha256: Result := 'rsa_pss_rsae_sha256';
    rsa_pss_rsae_sha384: Result := 'rsa_pss_rsae_sha384';
    rsa_pss_rsae_sha512: Result := 'rsa_pss_rsae_sha512';
    ed25519: Result := 'ed25519';
    ed448: Result := 'ed448';
    rsa_pss_pss_sha256: Result := 'rsa_pss_pss_sha256';
    rsa_pss_pss_sha384: Result := 'rsa_pss_pss_sha384';
    rsa_pss_pss_sha512: Result := 'rsa_pss_pss_sha512';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetSignatureAndHashAlgorithm(const Value: TSignatureAndHashAlgorithm): string;
begin
  Result := GetHashAlgorithm(Value.Hash) + ' + ' + GetSignatureAlgorithm(Value.Signature)
end;

function GetSupportedGroup(Value: TSupportedGroup): string;
begin
  case Value of
    sect163k1 : Result := 'sect163k1';
    sect163r1 : Result := 'sect163r1';
    sect163r2 : Result := 'sect163r2';
    sect193r1 : Result := 'sect193r1';
    sect193r2 : Result := 'sect193r2';
    sect233k1 : Result := 'sect233k1';
    sect233r1 : Result := 'sect233r1';
    sect239k1 : Result := 'sect239k1';
    sect283k1 : Result := 'sect283k1';
    sect283r1 : Result := 'sect283r1';
    sect409k1 : Result := 'sect409k1';
    sect409r1 : Result := 'sect409r1';
    sect571k1 : Result := 'sect571k1';
    sect571r1 : Result := 'sect571r1';
    secp160k1 : Result := 'secp160k1';
    secp160r1 : Result := 'secp160r1';
    secp160r2 : Result := 'secp160r2';
    secp192k1 : Result := 'secp192k1';
    secp192r1 : Result := 'secp192r1';
    secp224k1 : Result := 'secp224k1';
    secp224r1 : Result := 'secp224r1';
    secp256k1 : Result := 'secp256k1';
    secp256r1 : Result := 'secp256r1';
    secp384r1 : Result := 'secp384r1';
    secp521r1 : Result := 'secp521r1';
    brainpoolP256r1 : Result := 'brainpoolP256r1';
    brainpoolP384r1 : Result := 'brainpoolP384r1';
    brainpoolP512r1 : Result := 'brainpoolP512r1';
    x25519 : Result := 'x25519';
    x448 : Result := 'x448';
    ffdhe2048: Result := 'ffdhe2048';
    ffdhe3072: Result := 'ffdhe3072';
    ffdhe4096: Result := 'ffdhe4096';
    ffdhe6144: Result := 'ffdhe6144';
    ffdhe8192: Result := 'ffdhe8192';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetECPointFormat(Value: TECPointFormat): string;
begin
  case Value of
    uncompressed: Result := 'uncompressed';
//    ansiX962_compressed_prime: Result := 'ansiX962_compressed_prime';
//    ansiX962_compressed_char2: Result := 'ansiX962_compressed_char2';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

//function GetSignatureScheme(Value: TSignatureScheme): string;
//begin
//  case Value of
//    rsa_pkcs1_sha256: Result := 'rsa_pkcs1_sha256';
//    rsa_pkcs1_sha384: Result := 'rsa_pkcs1_sha384';
//    rsa_pkcs1_sha512: Result := 'rsa_pkcs1_sha512';
//    ecdsa_secp256r1_sha256: Result := 'ecdsa_secp256r1_sha256';
//    ecdsa_secp384r1_sha384: Result := 'ecdsa_secp384r1_sha384';
//    ecdsa_secp521r1_sha512: Result := 'ecdsa_secp521r1_sha512';
//    rsa_pss_rsae_sha256: Result := 'rsa_pss_rsae_sha256';
//    rsa_pss_rsae_sha384: Result := 'rsa_pss_rsae_sha384';
//    rsa_pss_rsae_sha512: Result := 'rsa_pss_rsae_sha512';
//    ed25519: Result := 'ed25519';
//    ed448: Result := 'ed448';
//    rsa_pss_pss_sha256: Result := 'rsa_pss_pss_sha256';
//    rsa_pss_pss_sha384: Result := 'rsa_pss_pss_sha384';
//    rsa_pss_pss_sha512: Result := 'rsa_pss_pss_sha512';
//    rsa_pkcs1_sha1: Result := 'rsa_pkcs1_sha1';
//    ecdsa_sha1: Result := 'ecdsa_sha1';
//    dsa_sha1_RESERVED: Result := 'dsa_sha1_RESERVED';
//  else
//    Result := '';
//  end;
//  Result := Result + ' (' + IntToStr(Ord(Value)) + ' / 0x' + IntToHex(Ord(Value), 4) + ')';
//end;
//
function GetCurveType(Value: TCurveType): string;
begin
  case Value of
    NamedCurve: Result := 'NamedCurve';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetAlertLevel(Value: TAlertLevel): string;
begin
  case Value of
    warning: Result := 'warning';
    fatal: Result := 'fatal';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetAlertDescription(Value: TAlertDescription): string;
begin
  case Value of
    close_notify: Result := 'close_notify';
    unexpected_message: Result := 'unexpected_message';
    bad_record_mac: Result := 'bad_record_mac';
    record_overflow: Result := 'record_overflow';
    decompression_failure: Result := 'decompression_failure';
    handshake_failure: Result := 'handshake_failure';
    bad_certificate: Result := 'bad_certificate';
    unsupported_certificate: Result := 'unsupported_certificate';
    certificate_revoked: Result := 'certificate_revoked';
    certificate_expired: Result := 'certificate_expired';
    certificate_unknown: Result := 'certificate_unknown';
    illegal_parameter: Result := 'illegal_parameter';
    unknown_ca: Result := 'unknown_ca';
    access_denied: Result := 'access_denied';
    decode_error: Result := 'decode_error';
    decrypt_error: Result := 'decrypt_error';
    export_restriction: Result := 'export_restriction';
    protocol_version: Result := 'protocol_version';
    insufficient_security: Result := 'insufficient_security';
    internal_error: Result := 'internal_error';
    user_canceled: Result := 'user_canceled';
    no_renegotiation: Result := 'no_renegotiation';
    unsupported_extension: Result := 'unsupported_extension';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

function GetClientCertificateType(Value: TClientCertificateType): string;
begin
  case Value of
    rsa_sign : Result := 'rsa_sign';
    dss_sign : Result := 'dss_sign';
    rsa_fixed_dh : Result := 'rsa_fixed_dh';
    dss_fixed_dh : Result := 'dss_fixed_dh';
    rsa_ephemeral_dh_RESERVED : Result := 'rsa_ephemeral_dh_RESERVED';
    dss_ephemeral_dh_RESERVED : Result := 'dss_ephemeral_dh_RESERVED';
    fortezza_dms_RESERVED : Result := 'fortezza_dms_RESERVED';
    ecdsa_sign : Result := 'ecdsa_sign';
    rsa_fixed_ecdh : Result := 'rsa_fixed_ecdh';
    ecda_fixed_ecdh : Result := 'ecda_fixed_ecdh';
  else
    Result := '';
  end;
  Result := Result + ' (' + IntToStr(Ord(Value)) + ')';
end;

end.

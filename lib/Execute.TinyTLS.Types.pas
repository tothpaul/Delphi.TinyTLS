unit Execute.TinyTLS.Types;
{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Hash,
  Execute.Sockets;

const
  TLS_10 = $0103; // 3.1 = TLS 1.0
  TLS_12 = $0303; // 3.3 = TLS 1.2
  TLS_13 = $0403; // 3.4 = TLS 1.3

  TLS_FRAGMENT_SIZE = 16384; // 2^14 = $4000
  TLS_MAX_FRAGMENT  = $7FFF;

type
  TProtocolStates = (
    psClientHello,
    psServerHello,
    psServerHelloDone,
    psHelloRequest
  );
  TProtocolState = set of TProtocolStates;

  TTLSFragment = array[0..TLS_MAX_FRAGMENT] of Byte;

// https://www.rfc-editor.org/rfc/rfc5246#section-6.2
  TContentType = (
    ChangeCipherSpec = 20,
    Alert            = 21,
    HandShake        = 22,
    ApplicationData  = 23
  );

  TProtocolVersion = packed record
  case Boolean of
    True : (major, minor: Byte);
    False: (code: Word);
  end;
  PProtocolVersion = ^TProtocolVersion;

  TTLSPlaintextHeader = packed record
    ContentType     : TContentType;
    ProtocolVersion : TProtocolVersion;
  private
    FLength         : Word;
    function GetLength: Word; inline;
    procedure SetLength(Value: Word); inline;
  public
    property Length: Word read GetLength write SetLength;
    function Fragment: Pointer;
    function IsCrypted: Boolean;
  end;
  PTLSPlaintextHeader = ^TTLSPlaintextHeader;

  TTLSPlaintext = packed record
    Header  : TTLSPlaintextHeader;
    Fragment: TTLSFragment;
  end;
  PTLSPlaintext = ^TTLSPlaintext;

  TAlertLevel = (
    warning = 1,
    fatal = 2
  );

  TAlertDescription = (
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,          // SEC_E_MESSAGE_ALTERED
    decryption_failed_RESERVED = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,       // no valid Cipher
    no_certificate_RESERVED = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,            // wrong ClientKeyExchange
    decrypt_error = 51,
    export_restriction = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    user_canceled = 90,
    no_renegotiation = 100,
    unsupported_extension = 110
  );

  TAlert = packed record
    level: TAlertLevel;
    description: TAlertDescription;
  end;
  PAlert = ^TAlert;

  ETLSAlert = class(Exception)
  private
    FAlert: TAlert;
  public
    constructor Create(const AAlert: TAlert; const Msg: string); overload;
    constructor Create(ALevel: TAlertLevel; ADescription: TAlertDescription; const Msg: string); overload;
    property Alert: TAlert read FAlert;
    property AlertLevel: TAlertLevel read FAlert.level;
    property AlertDescription: TAlertDescription read FALert.description;
  end;

  TUnsignedInteger24 = packed record
  private
    FPad: Byte;
    FSize: Word;
    function GetValue: Word; inline;
    procedure SetValue(Value: Word); inline;
  public
    property Value: Word read GetValue write SetValue;
  end;
  PUnsignedInteger24 = ^TUnsignedInteger24;

  THandshakeType = (
    HelloRequest          = 0,
    ClientHello           = 1,
    ServerHello           = 2,
    NewSessionTicket      = 4, // TLS 1.3
    Certificate           = 11,
    ServerKeyExchange     = 12,
    CertificateRequest    = 13,
    ServerHelloDone       = 14,
    CertificateVerify     = 15,
    ClientKeyExchange     = 16,
    Finished              = 20
  );

  THandShakeHeader = packed record
    HandShakeType : THandShakeType;
  private
    FLength        : TUnsignedInteger24;
    function GetLength: Word; inline;
    procedure SetLength(Value: Word); inline;
  public
    property Length: Word read GetLength write SetLength;
    function Payload: Pointer;
  end;
  PHandShakeHeader = ^THandShakeHeader;

  // TLS1.2 Signature and Algorithm (Signature Schemes in TLS 1.3)

  THashAlgorithm = (
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6,
    Intrinsic = 8
  );

  TRandom = packed record
    Time : Cardinal;
    Data : array[0..27] of Byte;
  end;

  TFinished = array[0..11] of Byte;
  PFinished = ^TFinished;

  TFinishedCache = packed record
    Len: Byte;
    Client: TFinished;
    Server: TFinished;
  end;

  IHashAlgorithm = interface
    function HashID: THashAlgorithm;
    function HashSize: Integer;
    function BlockSize: Integer;
    procedure Update(Data: Pointer; Size: Cardinal); overload;
    function Digest: TBytes;
    function Hash(Data: Pointer; Size: Cardinal): TBytes;
    function HMAC(const AData, AKey: TBytes): TBytes;
    procedure PRF(const ASeed, ASecret: TBytes; var AData; ALen: Integer); overload;
    procedure PRF(const ALabel: AnsiString; const ARandom, ASecret: TBytes; var AData; ALen: Integer); overload;
    procedure PRF(const ALabel: AnsiString; const ARandom1, ARandom2: TRandom; const ASecret: TBytes; var AData; ALen: Integer); overload;
  end;

  TCustomHashAlgorithm = class(TInterfacedObject)
    procedure PRF(const ASeed, ASecret: TBytes; var AData; ALen: Integer); overload; virtual; abstract;
    procedure PRF(const ALabel: AnsiString; const ARandom, ASecret: TBytes; var AData; ALen: Integer); overload;
    procedure PRF(const ALabel: AnsiString; const ARandom1, ARandom2: TRandom; const ASecret: TBytes; var AData; ALen: Integer); overload;
  end;

  TSHA1Hash = class(TCustomHashAlgorithm, IHashAlgorithm)
  private
    FHash: THashSHA1;
  public
    constructor Create;
    function HashID: THashAlgorithm;
    function HashSize: Integer;
    function BlockSize: Integer;
    procedure Update(Data: Pointer; Size: Cardinal); overload;
    function Digest: TBytes;
    function Hash(Data: Pointer; Size: Cardinal): TBytes;
    function HMAC(const AData, AKey: TBytes): TBytes;
    procedure PRF(const ASeed, ASecret: TBytes; var AData; ALen: Integer); override;
  end;

  TSHA2Hash = class(TCustomHashAlgorithm, IHashAlgorithm)
  private
    Version: THashSHA2.TSHA2Version;
    FHash: THashSHA2;
  public
    constructor Create(BitCount: Integer);
    function HashID: THashAlgorithm;
    function HashSize: Integer;
    function BlockSize: Integer;
    procedure Update(Data: Pointer; Size: Cardinal); overload;
    function Digest: TBytes;
    function Hash(Data: Pointer; Size: Cardinal): TBytes;
    function HMAC(const AData, AKey: TBytes): TBytes;
    procedure PRF(const ASeed, ASecret: TBytes; var AData; ALen: Integer); override;
  end;

  ICipherAlgorithm = interface
    procedure SetMasterSecret(const ClientRandom, ServerRandom: TRandom; const MasterSecret: TBytes; const Hash: IHashAlgorithm);
    function MaxSize: Cardinal;
    function EncryptSize(Size: Cardinal): Cardinal;
    procedure Decrypt(var APlaintext: PTLSPlaintextHeader);
    procedure Encrypt(Plaintext: PTLSPlaintextHeader);
  end;

  TCipherSuiteTag = (
    TLS_RSA_WITH_RC4_128_MD5                = $0004,
    TLS_RSA_WITH_RC4_128_SHA                = $0005,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA           = $000A,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       = $0013,
    TLS_RSA_WITH_AES_128_CBC_SHA            = $002F,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA        = $0032,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA        = $0033,
    TLS_RSA_WITH_AES_256_CBC_SHA            = $0035,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA        = $0038,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA        = $0039,
    TLS_RSA_WITH_AES_128_CBC_SHA256         = $003C,
    TLS_RSA_WITH_AES_256_CBC_SHA256         = $003D,
    TLS_RSA_WITH_AES_128_GCM_SHA256         = $009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384         = $009D,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     = $009E,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     = $009F,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV       = $00FF,
    TLS_AES_128_GCM_SHA256                  = $1301,
    TLS_AES_256_GCM_SHA384                  = $1302,
    TLS_CHACHA20_POLY1305_SHA256            = $1303,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    = $C009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    = $C00A,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      = $C013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      = $C014,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = $C023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = $C024,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   = $C027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = $C028,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = $C02C,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = $C02B,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = $C02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   = $C030
  );

  IClientKeyExchangeAlgorithm = interface
    function PreMasterSecret: TBytes;
    function ClientKey: TBytes;
    procedure SetRemoteKey(const Value: TBytes);
  end;

  TCurveName = (
    NoCurve   = 0,
    sect163k1 = 1,
    sect163r1 = 2,
    sect163r2 = 3,
    sect193r1 = 4,
    sect193r2 = 5,
    sect233k1 = 6,
    sect233r1 = 7,
    sect239k1 = 8,
    sect283k1 = 9,
    sect283r1 = 10,
    sect409k1 = 11,
    sect409r1 = 12,
    sect571k1 = 13,
    sect571r1 = 14,
    secp160k1 = 15,
    secp160r1 = 16,
    secp160r2 = 17,
    secp192k1 = 18,
    secp192r1 = 19,
    secp224k1 = 20,
    secp224r1 = 21,
    secp256k1 = 22,
    secp256r1 = 23,
    secp384r1 = 24,
    secp521r1 = 25,
    brainpoolP256r1 = 26,
    brainpoolP384r1 = 27,
    brainpoolP512r1 = 28,
    x25519 = 29,
    x448 = 30,
    ffdhe2048 = 256,
    ffdhe3072 = 257,
    ffdhe4096 = 258,
    ffdhe6144 = 259,
    ffdhe8192 = 260
  );
  TSupportedGroup = TCurveName;

  TSignatureAlgorithm = (
    anonymous = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
    ed25519_ = 7,
    ed448_ = 8,
    gostr34102012_256 = 64,
    gostr34102012_512 = 65
  );

 // TLS 1.3 Signature Schemes (replace TLS 1.2 Signature And Algorithm)

  TSignatureScheme = (
    rsa_pkcs1_sha1 = $0201,   // rsa + sha1
    TLS12_dsa_sha1 = $0202,
    ecdsa_sha1 = $0203,
    rsa_pkcs1_sha256 = $0401, // rsa + sha256
    TLS12_dsa_sha256 = $0402,
    rsa_pkcs1_sha384 = $0501, // rsa + sha384
    TLS12_dsa_sha384 = $0502,
    rsa_pkcs1_sha512 = $0601, // rsa + sha512
    ecdsa_secp254r1_sha256 = $0403,
    ecdsa_secp384r1_sha384 = $0503,
    TLS12_dsa_sha512 = $0602,
    ecdsa_secp521r1_sha512 = $0603,
    rsa_pss_sha256 = $0700,
    rsa_pss_sha384 = $0701,
    rsa_pss_sha512 = $0702,
    TLS13_ed25519 = $0703,
    TLS13_ed448 = $0704,
    rsa_pss_rsae_sha256 = $0804,
    rsa_pss_rsae_sha384 = $0805,
    rsa_pss_rsae_sha512 = $0806,
    ed25519 = $0807,
    ed448 = $0808,
    rsa_pss_pss_sha256 = $0809,
    rsa_pss_pss_sha384 = $080a,
    rsa_pss_pss_sha512 = $080b
  );

  TClientCertificateType = (
  // RFC 2246
    rsa_sign = 1,
    dss_sign = 2,
    rsa_fixed_dh = 3,
    dss_fixed_dh = 4,
  // RFC 4346
    rsa_ephemeral_dh_RESERVED = 5,
    dss_ephemeral_dh_RESERVED = 6,
    fortezza_dms_RESERVED = 20,
  // RFC 4492, RFC8442
    ecdsa_sign = $40,
    rsa_fixed_ecdh = $41,
    ecda_fixed_ecdh = $42
  );

  TCompressionMethodTag = (
    Null = 0
  );

  TCompressionList = packed record
    Count: Byte;
    Items: array[Byte] of TCompressionMethodTag;
    class function SizeFor(const Compressions: TArray<TCompressionMethodTag>): Integer; static;
    procedure SetCompressions(const Compressions: TArray<TCompressionMethodTag>);
  end;
  PCompressionList = ^TCompressionList;

  TCipherList = packed record
  private
    FSize: Word;
    FItems: array[Word] of Word;
    function GetSize: Word;
    function GetCount: Word;
    procedure SetCount(Value: Word);
    function GetTag(Index: Integer): TCipherSuiteTag;
    procedure SetTag(Index: Integer; Value: TCipherSuiteTag);
  public
    class function SizeFor(const Ciphers: TArray<TCipherSuiteTag>): Integer; static;
    procedure SetCiphers(const Ciphers: TArray<TCipherSuiteTag>);
    function Contains(Cipher: TCipherSuiteTag): Boolean;
    property Items[Index: Integer]: TCipherSuiteTag read GetTag write SetTag;
    property Size: Word read GetSize;
    property Count: Word read GetCount write SetCount;
  end;
  PCipherList = ^TCipherList;

  TMasterSecret = array[0..47] of Byte;

  IServerContext = interface
    procedure InitRandom(var Random: TRandom);
    function SetCipherSuite(CipherSuite: TCipherSuiteTag): Boolean;
    function HashAlgorithm: IHashAlgorithm;
    function CipherAlgorithm: ICipherAlgorithm;
    function ClientKeyExchangeAlgorithm: IClientKeyExchangeAlgorithm;
    procedure VerifyServer(const AHost: UTF8String; const ACertificates: TArray<TBytes>);
    procedure ComputeMasterSecret(var ClientRandom, ServerRandom: TRandom; var MasterSecret: TBytes);
    procedure ComputeFinished(ALabel: AnsiString; HandShakeData: TMemoryStream; const MasterSecret: TBytes; var Finished: TFinished);
    procedure VerifySignature(NamedCurve: TCurveName; const PublicKey: TBytes; SignatureScheme: TSignatureScheme; const Digest, Sign: TBytes);
  // TLS 1.3
    function GetPublicKey(NamedCurve: TCurveName): TBytes;
    procedure SetRemoteKey(const Value: TBytes);
  end;

  // Read TSL fragments from input socket
  TTLSReader = class(TThread)
  private
    FSocket: TSocket;
    FData  : TEvent;
    FDone  : TEvent;
    FBuffer: TBytes;
    FStart : Integer;
    FTail  : Integer;
    FCount : Integer;
    FPlaintext: PTLSPlainTextHeader;
    function FillBuffer: Integer;
    procedure PackBuffer;
  protected
    procedure TerminatedSet; override;
  public
    constructor Create(ASocket: TSocket);
    destructor Destroy; override;
    procedure Execute; override;
    function WaitFor(Timeout: Cardinal): TWaitResult;
    property Plaintext: PTLSPlainTextHeader read FPlaintext;
    property Socket: TSocket read FSocket;
    property Done: TEvent read FDone;
  end;

procedure RaiseHandShakeFailure(const Name: string);
procedure CheckProtocol(const Protocol: TProtocolVersion; ExpectedVersion: Word);
procedure RaiseOverflow(const Name: string);
procedure RaiseDecodeError(const Name: string);

function LSwap(L: Cardinal): Cardinal;
function LLSwap(L: UInt64): UInt64;

implementation

procedure RaiseHandShakeFailure(const Name: string);
begin
  raise ETLSAlert.Create(TAlertLevel.fatal, TAlertDescription.handshake_failure, Name + ' handshake failure');
end;

procedure CheckProtocol(const Protocol: TProtocolVersion; ExpectedVersion: Word);
begin
  if Protocol.code <> ExpectedVersion then
    RaiseHandShakeFailure('Unexpected protocol version ' + IntToStr(Protocol.major) + '.' + IntToStr(Protocol.minor));
end;

procedure RaiseOverflow(const Name: string);
begin
  raise ETLSAlert.Create(TAlertLevel.fatal, TAlertDescription.record_overflow, Name + ' overflow');
end;

procedure RaiseDecodeError(const Name: string);
begin
  raise ETLSAlert.Create(TAlertLevel.fatal, TAlertDescription.decode_error, Name + ' decode error');
end;

function LSwap(L: Cardinal): Cardinal;
begin
  Result := Cardinal(Swap(L)) shl 16 + Swap(L shr 16);
end;

function LLSwap(L: UInt64): UInt64;
begin
  Result := UInt64(LSwap(L)) shl 32 + LSwap(L shr 32);
end;

{ TTLSPlaintextHeader }

function TTLSPlaintextHeader.GetLength: Word;
begin
  Result := Swap(FLength);
end;

function TTLSPlaintextHeader.IsCrypted: Boolean;
begin
  case ContentType of
    TContentType.ChangeCipherSpec : Result := Length <> 1;
    TContentType.Alert: Result := Length <> SizeOf(TAlert);
    TContentType.HandShake: Result := Length <> SizeOf(THandshakeHeader) + PHandShakeHeader(Fragment).Length;
  else
    Result := True;
  end;
end;

procedure TTLSPlaintextHeader.SetLength(Value: Word);
begin
  FLength := Swap(Value);
end;

function TTLSPlaintextHeader.Fragment: Pointer;
begin
  Result := @PByte(@Self)[SizeOf(Self)];
end;

{ ETLSAlert }

constructor ETLSAlert.Create(const AAlert: TAlert; const Msg: string);
begin
  FAlert := AAlert;
  inherited Create(Msg);
end;

constructor ETLSAlert.Create(ALevel: TAlertLevel;
  ADescription: TAlertDescription; const Msg: string);
begin
  FAlert.level := ALevel;
  FAlert.description := ADescription;
  inherited Create(Msg);
end;

{ TUnsignedInteger24 }

function TUnsignedInteger24.GetValue: Word;
begin
  Result := Swap(FSize);
end;

procedure TUnsignedInteger24.SetValue(Value: Word);
begin
  Assert(Value <= $7FFF);
  FSize := Swap(Value);
  FPad := 0;
end;

{ THandshakeHeader }

function THandshakeHeader.GetLength: Word;
begin
  Result := FLength.GetValue;
end;

procedure THandshakeHeader.SetLength(Value: Word);
begin
  FLength.SetValue(Value);
end;

function THandshakeHeader.Payload: Pointer;
begin
  Result := @PByte(@Self)[SizeOf(Self)];
end;

{ TCustomHashAlgorithm }

procedure TCustomHashAlgorithm.PRF(const ALabel: AnsiString; const ARandom, ASecret: TBytes; var AData; ALen: Integer);
begin
  var Seed: TBytes;
  SetLength(Seed, Length(ALabel) + Length(ARandom));
  Move(ALabel[1], Seed[0], Length(ALabel));
  Move(PByte(ARandom)^, Seed[Length(ALabel)], Length(ARandom));
  PRF(Seed, ASecret, AData, ALen);
end;

procedure TCustomHashAlgorithm.PRF(const ALabel: AnsiString; const ARandom1, ARandom2: TRandom; const ASecret: TBytes; var AData; ALen: Integer);
begin
  var Random: TBytes;
  SetLength(Random, SizeOf(ARandom1) + SizeOf(ARandom2));
  Move(ARandom1, Random[0], SizeOf(ARandom1));
  Move(ARandom2, Random[SizeOf(ARandom1)], SizeOf(ARandom2));

  PRF(ALabel, Random, ASecret, AData, ALen);
end;

{ TSHA1Hash }

constructor TSHA1Hash.Create;
begin
  FHash := THashSHA1.Create;
end;

function TSHA1Hash.HashID: THashAlgorithm;
begin
  Result := THashAlgorithm.sha1;
end;

function TSHA1Hash.HashSize: Integer;
begin
  Result := FHash.GetHashSize;
end;

function TSHA1Hash.BlockSize: Integer;
begin
  Result := FHash.GetBlockSize;
end;

procedure TSHA1Hash.Update(Data: Pointer; Size: Cardinal);
begin
  FHash.Update(Data^, Size);
end;

function TSHA1Hash.Digest: TBytes;
begin
  Result := FHash.HashAsBytes;
  FHash.Reset;
end;

function TSHA1Hash.Hash(Data: Pointer; Size: Cardinal): TBytes;
begin
  var H := THashSHA1.Create;
  H.Update(Data^, Size);
  Result := H.HashAsBytes;
end;

function TSHA1Hash.HMAC(const AData, AKey: TBytes): TBytes;
begin
  Result := THashSHA1.GetHMACAsBytes(AData, AKey);
end;

procedure TSHA1Hash.PRF(const ASeed, ASecret: TBytes; var AData; ALen: Integer);
begin
  var L := FHash.GetHashSize;
  var N := (ALen + (L - 1)) div L;

  var A := ASeed;
  var P := PByte(@AData);
  for var I := 1 to N do
  begin
    A := THashSHA1.GetHMACAsBytes(A, ASecret);
    var B := THashSHA1.GetHMACAsBytes(A + ASeed, ASecret);
    var C := L;
    if C > ALen then
      C := ALen;
    Move(B[0], P^, C);
    Inc(P, C);
    Dec(ALen, C);
  end;
end;

{ TSHA2Hash }

constructor TSHA2Hash.Create(BitCount: Integer);
begin
  case BitCount of
    224: Version := THashSHA2.TSHA2Version.SHA224;
    256: Version := THashSHA2.TSHA2Version.SHA256;
    384: Version := THashSHA2.TSHA2Version.SHA384;
    512: Version := THashSHA2.TSHA2Version.SHA512;
  else
    raise Exception.Create('Unsupported BitCount');
  end;
  FHash := THashSHA2.Create(Version);
end;

function TSHA2Hash.HashID: THashAlgorithm;
begin
  case Version of
    THashSHA2.TSHA2Version.SHA224: Result := THashAlgorithm.sha224;
    THashSHA2.TSHA2Version.SHA256: Result := THashAlgorithm.sha256;
    THashSHA2.TSHA2Version.SHA384: Result := THashAlgorithm.sha384;
    THashSHA2.TSHA2Version.SHA512: Result := THashAlgorithm.sha512;
  else
    raise Exception.Create('Internal error');
  end;
end;

function TSHA2Hash.HashSize: Integer;
begin
  Result := FHash.GetHashSize;
end;

function TSHA2Hash.BlockSize: Integer;
begin
  Result := FHash.GetBlockSize;
end;

procedure TSHA2Hash.Update(Data: Pointer; Size: Cardinal);
begin
  FHash.Update(Data^, Size);
end;

function TSHA2Hash.Digest: TBytes;
begin
  Result := FHash.HashAsBytes;
  FHash.Reset;
end;

function TSHA2Hash.Hash(Data: Pointer; Size: Cardinal): TBytes;
begin
  var H := THashSHA2.Create(Version);
  H.Update(Data^, Size);
  Result := H.HashAsBytes;
end;

function TSHA2Hash.HMAC(const AData, AKey: TBytes): TBytes;
begin
  Result := THashSHA2.GetHMACAsBytes(AData, AKey, Version);
end;

procedure TSHA2Hash.PRF(const ASeed, ASecret: TBytes; var AData; ALen: Integer);
begin
  var L := FHash.GetHashSize;
  var N := (ALen + (L - 1)) div L;

  var A := ASeed;
  var P := PByte(@AData);
  for var I := 1 to N do
  begin
    A := THashSHA2.GetHMACAsBytes(A, ASecret, Version);
    var B := THashSHA2.GetHMACAsBytes(A + ASeed, ASecret, Version);
    var C := L;
    if C > ALen then
      C := ALen;
    Move(B[0], P^, C);
    Inc(P, C);
    Dec(ALen, C);
  end;
end;

{ TTLSReader }

constructor TTLSReader.Create(ASocket: TSocket);
begin
  FSocket := ASocket;
  FData := TEvent.Create();
  FDone := TEvent.Create();
  inherited Create;
  FreeOnTerminate := True;
end;

destructor TTLSReader.Destroy;
begin
  inherited;
  FData.Free;
  FDone.Free;
end;

procedure TTLSReader.TerminatedSet;
begin
  FDone.SetEvent;
end;

procedure TTLSReader.Execute;
begin
  SetLength(FBuffer, $10000);
  while FillBuffer > 0 do
  begin
  // Need at least the header
    while FCount >= SizeOf(TTLSPlaintextHeader) do
    begin
      FPlaintext := @FBuffer[FStart];
    // Verify the fragment size
      var Len := SizeOf(TTLSPlaintextHeader) + FPlaintext.Length;
      if FCount < Len then
      begin
      // need more space in the buffer ?
        if FStart + Len > Length(FBuffer) then
          PackBuffer;
        Break;
      end;
    // A new fragment is available
      FData.SetEvent;
      if Terminated then
        Exit;
    // Wait until it is processed
      FDone.WaitFor(INFINITE);
      FDone.ResetEvent;
      Dec(FCount, Len);
      if FCount = 0 then
      begin
        FStart := 0;
        FTail := 0;
      end else begin
        Inc(FStart, Len);
      end;
    end;
  end;
// Notification of termination
  FPlaintext := nil;
  FData.SetEvent;
  if not Terminated then
    FDone.WaitFor(INFINITE);
end;

function TTLSReader.FillBuffer: Integer;
begin
  Result := FSocket.Read(FBuffer[FTail], Length(FBuffer) - FTail, True);
  if Result > 0 then
  begin
    Inc(FTail, Result);
    FCount := FTail - FStart;
  end;
end;

procedure TTLSReader.PackBuffer;
begin
  Move(FBuffer[FStart], FBuffer[0], FCount);
  FStart := 0;
  FTail := FCount;
end;

function TTLSReader.WaitFor(Timeout: Cardinal): TWaitResult;
begin
  Result := FData.WaitFor(Timeout);
  if Result = wrSignaled then
  begin
    FData.ResetEvent;
    if FPlaintext = nil then
    begin
      Terminate;
      raise Exception.Create('TLS Read');
    end;
  end;
end;

{ TCompressionList }

procedure TCompressionList.SetCompressions(
  const Compressions: TArray<TCompressionMethodTag>);
begin
  Count := Length(Compressions);
  for var I := 0 to Length(Compressions) - 1 do
    Items[I] := Compressions[I];
end;

class function TCompressionList.SizeFor(
  const Compressions: TArray<TCompressionMethodTag>): Integer;
begin
  Result := SizeOf(Byte { Size }) + Length(Compressions) * SizeOf(TCompressionMethodTag)
end;

{ TCipherList }

class function TCipherList.SizeFor(const Ciphers: TArray<TCipherSuiteTag>): Integer;
begin
  Result := SizeOf(Word { FSize}) + Length(Ciphers) * SizeOf(TCipherSuiteTag);
end;

function TCipherList.GetTag(Index: Integer): TCipherSuiteTag;
begin
  Result := TCipherSuiteTag(Swap(FItems[Index]));
end;

procedure TCipherList.SetTag(Index: Integer; Value: TCipherSuiteTag);
begin
  FItems[Index] := Swap(Ord(Value));
end;

function TCipherList.Contains(Cipher: TCipherSuiteTag): Boolean;
begin
  for var I := 0 to Count - 1 do
    if Items[I] = Cipher then
      Exit(True);
  Result := False;
end;

function TCipherList.GetSize: Word;
begin
  Result := Swap(FSize);
end;

function TCipherList.GetCount: Word;
begin
  Result := Swap(FSize) div SizeOf(Word);
end;

procedure TCipherList.SetCiphers(const Ciphers: TArray<TCipherSuiteTag>);
begin
  Count := Length(Ciphers);
  for var I := 0 to Length(Ciphers) - 1 do
    Items[I] := Ciphers[I];
end;

procedure TCipherList.SetCount(Value: Word);
begin
  FSize := Swap(Value * SizeOf(Word));
end;

end.

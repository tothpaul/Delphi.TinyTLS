unit Execute.TinyTLS.Win.Ciphers;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}


interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.DateUtils,
  Execute.TinyTLS.Types,
  Execute.Winapi.BCrypt;

type
  ECertException = class(Exception)
  private
    FStatus: HRESULT;
  public
    constructor Create(const Msg: string; Err: HRESULT);
    property Status: HRESULT read FStatus;
  end;

  TEncryptIV = array[0..3] of Byte;

  TGCMRandom = array[0..7] of Byte;

  TGCMNonce = packed record
    IV    : TEncryptIV;
    Random: TGCMRandom;
  end;

  TAESData = packed record
    SeqNum: UInt64;
    Header: TTLSPlaintextHeader;
  end;
  PAESData = ^TAESData;

  TGCMHeader = record
    Random : TGCMRandom;
    Data   : array[Word] of Byte;
  end;
  PGCMHeader = ^TGCMHeader;

  TAESTag = packed array[0..15] of Byte;

  TVerifyServerEvent = procedure(Sender: TObject; const Certificates: TArray<TBytes>; Context: PCCERT_CONTEXT; ChainContext: PCCERT_CHAIN_CONTEXT; var Status: CERT_CHAIN_POLICY_STATUS) of object;

  TCustomRSAClientKeyExchange = class(TInterfacedObject)
  private
    FPreMasterSecret: TBytes;
  public
    function PreMasterSecret: TBytes;
  end;

  TRSAClientKeyExchange = class(TCustomRSAClientKeyExchange, IClientKeyExchangeAlgorithm)
    FPubKey: BCRYPT_KEY_HANDLE;
    constructor Create(Key: BCRYPT_KEY_HANDLE);
    function ClientKey: TBytes;
    procedure SetRemoteKey(const Key: TBytes);
  end;

  TECCKey = record
    Blob: TBytes;
    Header: PBCRYPT_ECCKEY_BLOB;
    PublicKey: PByte;
    procedure Import(hKeyPair: BCRYPT_KEY_HANDLE; BlobType: LPCWSTR);
    procedure SetKeyType(Magic, Size: ULONG);
    function ExportKey(hAlg: THandle): BCRYPT_KEY_HANDLE;
  end;

  TECDHE_RSAKeyExchange = class(TCustomRSAClientKeyExchange, IClientKeyExchangeAlgorithm)
    KeySize: Integer;
    hAlg: BCRYPT_ALG_HANDLE;
    ECCPrivateKey: TECCKey;
    ECCPublicKey: TECCKey;
    ECCRemoteKey: TECCKey; // TECCPublicKey;
    constructor Create(ACurveName: TCurveName); overload;
    constructor Create(ACurveName: TCurveName; const Key: TBytes); overload;
    procedure SetRemoteKey(const Value: TBytes);
    destructor Destroy; override;
    function ClientKey: TBytes;
  end;

  TCustomAESCipher = class(TInterfacedObject)
    KeySize: Cardinal;
    KeyBlock: TBytes;
    EncrKey: PUCHAR;
    DecrKey: PUCHAR;
    LocalIV: PByte;
    RemoteIV: PByte;
    AlgHandle: THandle;
    EncrKeyHandle: THandle;
    DecrKeyHandle: THandle;
    DecryptSeqNum: UInt64;
    EncryptSeqNum: UInt64;
    procedure SetMasterSecret(const ClientRandom, ServerRandom: TRandom; const MasterSecret: TBytes; const Hash: IHashAlgorithm);
  end;

  TAESCipherGCM = class(TCustomAESCipher, ICipherAlgorithm)
    GCMNonce: TGCMNonce;
    AESData: TAESData;
    AuthInfo: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
    Decrypted: TTLSPlaintext;
    constructor Create(BitSize: Integer; ServerSide: Boolean = False);
    function MaxSize: Cardinal;
    function EncryptSize(Size: Cardinal): Cardinal;
    procedure Decrypt(var APlaintext: PTLSPlaintextHeader);
    procedure Encrypt(Plaintext: PTLSPlaintextHeader);
  end;

  TAESCipherCBC = class(TCustomAESCipher, ICipherAlgorithm)
    HashAlgo: IHashAlgorithm;
    HashSize: Cardinal;
    HashKey : TBytes;
    IVSize: Cardinal;
    EncrHash: PByte;
    DecrHash: PByte;
    IV, IV2: TBytes;
    Plaintext: TTLSPlaintext;
    constructor Create(BitSize: Integer; HashAlgorithm: IHashAlgorithm; ServerSide: Boolean = False);
    function MaxSize: Cardinal;
    function EncryptSize(Size: Cardinal): Cardinal;
    function HMAC(Key: PByte; Plaintext: PTLSPlaintextHeader; var SeqNum: UInt64): TBytes;
    procedure Decrypt(var APlaintext: PTLSPlaintextHeader);
    procedure Encrypt(APlaintext: PTLSPlaintextHeader);
  end;

  TServerContext = class(TInterfacedObject, IServerContext)
  private
    FCipherSuite: TCipherSuiteTag;
    FHashAlgorithm: IHashAlgorithm;
    FCipherAlgorithm: ICipherAlgorithm;
    FKeyExchangeAlgorithm: IClientKeyExchangeAlgorithm;
    FContext: PCCERT_CONTEXT;
    FPubKey: BCRYPT_KEY_HANDLE;
    FOnVerifyServer: TVerifyServerEvent;
  public
    destructor Destroy; override;
    procedure InitRandom(var Random: TRandom);
    function SetCipherSuite(CipherSuite: TCipherSuiteTag): Boolean;
    function HashAlgorithm: IHashAlgorithm;
    function CipherAlgorithm: ICipherAlgorithm;
    function ClientKeyExchangeAlgorithm: IClientKeyExchangeAlgorithm;
    procedure ComputeMasterSecret(var ClientRandom, ServerRandom: TRandom; var MasterSecret: TBytes);
    procedure ComputeFinished(ALabel: AnsiString; HandShakeData: TMemoryStream; const MasterSecret: TBytes; var Finished: TFinished);
    procedure VerifyServer(const AHost: UTF8String; const ACertificates: TArray<TBytes>);
    procedure VerifySignature(NamedCurve: TCurveName; const PublicKey: TBytes; SignatureScheme: TSignatureScheme; const Digest, Sign: TBytes);
    function GetPublicKey(NamedCurve: TCurveName): TBytes;
    procedure SetRemoteKey(const Value: TBytes);
    property OnVerifyServer: TVerifyServerEvent read FOnVerifyServer write FOnVerifyServer;
  end;

procedure ReverseArray(var A: TBytes);

implementation

procedure ReverseArray(var A: TBytes);
begin
  var L := Length(A);
  var N := (L div 2) - 1;
  Dec(L);
  for var I := 0 to N do
  begin
    var J := L - I;
    var T := A[I];
    A[I] := A[J];
    A[J] := T;
  end;
end;

procedure NTSTATUSCheck(Status: NTSTATUS);
begin
  if Status <> 0 then
  begin
    ETLSAlert.Create(TAlertLevel.fatal, TAlertDescription.decrypt_error, NTSTATUSText(Status));
  end;
end;

{ ECertException }

constructor ECertException.Create(const Msg: string; Err: HRESULT);
begin
  FStatus := Err;
  inherited Create(Msg);
end;

{ TCustomRSAClientKeyExchange }

function TCustomRSAClientKeyExchange.PreMasterSecret: TBytes;
begin
  Result := FPreMasterSecret;
end;

{ TRSAClientKeyExchange }

const
  VERSION_MAJOR = 3; // 3.3 = TLS 1.2
  VERSION_MINOR = 3;

constructor TRSAClientKeyExchange.Create(Key: BCRYPt_KEY_HANDLE);
begin
  SetLength(FPreMasterSecret, 48);
  FPreMasterSecret[0] := VERSION_MAJOR;
  FPreMasterSecret[1] := VERSION_MINOR;
  FillRandom(FPreMasterSecret[2], Length(FPreMasterSecret) - 2);
  FPubKey := Key;
end;

procedure TRSAClientKeyExchange.SetRemoteKey(const Key: TBytes);
begin
  raise Exception.Create('TRSAClientKeyExchange.SetRemoteKey');
end;

function TRSAClientKeyExchange.ClientKey: TBytes;
begin
  var Len := 256;
  SetLength(Result, 2 + Len);
  PWord(Result)^ := Swap(Len);
  NTSTATUSCheck(BCryptEncrypt(FPubKey, PUCHAR(FPreMasterSecret), Length(FPreMasterSecret), nil, nil, 0, PUCHAR(@Result[2]), Len, @Len, BCRYPT_PAD_PKCS1));
end;

{ TECCKey }

function TECCKey.ExportKey(hAlg: THandle): BCRYPT_KEY_HANDLE;
begin
  var BlobType: LPCWSTR;
  if Header.dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC then
    BlobType := BCRYPT_ECCPUBLIC_BLOB
  else
    BlobType := BCRYPT_ECCPRIVATE_BLOB;
  NTSTATUSCheck(BCryptImportKeyPair(hAlg, 0, BlobType, Result, PUCHAR(Blob), Length(Blob), 0));
end;

procedure TECCKey.Import(hKeyPair: BCRYPT_KEY_HANDLE; BlobType: LPCWSTR);
begin
  var Size: ULONG;
  NTSTATUSCheck(BCryptExportKey(hKeyPair, 0, BlobType, nil, 0, @Size, 0));
  SetLength(Blob, Size);
  NTSTATUSCheck(BCryptExportKey(hKeyPair, 0, BlobType, PUCHAR(Blob), Size, @Size, 0));
  Header := PBCRYPT_ECCKEY_BLOB(Blob);
  PublicKey := @Blob[SizeOf(BCRYPT_ECCKEY_BLOB)];
end;

procedure TECCKey.SetKeyType(Magic, Size: ULONG);
begin
  if Magic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC then
    SetLength(Blob, SizeOf(BCRYPT_ECCKEY_BLOB) + 2 * Size)
  else
    SetLength(Blob, SizeOf(BCRYPT_ECCKEY_BLOB) + 3 * Size);
  Header := PBCRYPT_ECCKEY_BLOB(Blob);
  Header.dwMagic := Magic;
  Header.cbKey := Size;
  PublicKey := @Blob[SizeOf(BCRYPT_ECCKEY_BLOB)];
end;

{ TECDHE_RSAKeyExchange }

constructor TECDHE_RSAKeyExchange.Create(ACurveName: TCurveName);
begin
  inherited Create;

  var hKeyPair: BCRYPT_KEY_HANDLE;

  case ACurveName of
    secp256r1:
    begin
      NTSTATUSCheck(BCryptOpenAlgorithmProvider(hAlg, BCRYPT_ECDH_P256_ALGORITHM, nil, 0));
      KeySize := 65;
    end;
    secp384r1:
    begin
      NTSTATUSCheck(BCryptOpenAlgorithmProvider(hAlg, BCRYPT_ECDH_P384_ALGORITHM, nil, 0));
      KeySize := 97;
    end;
    x25519:
    begin
      NTSTATUSCheck(BCryptOpenAlgorithmProvider(hAlg, BCRYPT_ECDH_ALGORITHM, nil, 0));
      NTSTATUSCheck(BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, PUCHAR(BCRYPT_ECC_CURVE_25519), (Length(BCRYPT_ECC_CURVE_25519) + 1) * SizeOf(Char), 0));
      KeySize := 32;
    end;
  else
    RaiseHandShakeFailure('Unsupported Curve');
  end;

  NTSTATUSCheck(BCryptGenerateKeyPair(hAlg, hKeyPair, 0, 0));
  NTSTATUSCheck(BCryptFinalizeKeyPair(hKeyPair, 0));

  ECCPrivateKey.Import(hKeyPair, BCRYPT_ECCPRIVATE_BLOB);
  ECCPublicKey.Import(hKeyPair, BCRYPT_ECCPUBLIC_BLOB);

  NTSTATUSCheck(BCryptDestroyKey(hKeyPair));
end;

constructor TECDHE_RSAKeyExchange.Create(ACurveName: TCurveName; const Key: TBytes);
begin
  Create(ACurveName);
  SetRemoteKey(Key);
end;

procedure TECDHE_RSAKeyExchange.SetRemoteKey(const Value: TBytes);
begin
  if Length(Value) <> KeySize then
    RaiseHandShakeFailure('ServerKey Size');

  if KeySize = 32 then
  begin
    ECCRemoteKey.SetKeyType(BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, 32);
    Move(Value[0], ECCRemoteKey.PublicKey^, 32)
  end else begin
    if Value[0] <> 4 then
      RaiseHandShakeFailure('ServerKey compression');
    ECCRemoteKey.SetKeyType(BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, KeySize div 2);
    Move(Value[1], ECCRemoteKey.PublicKey^, KeySize - 1);
  end;

  var hPrivateKey := ECCPrivateKey.ExportKey(hAlg);
  var hPublicKey := ECCRemoteKey.ExportKey(hAlg);
  var hSecret: THandle;
  var Size: ULONG;

  NTSTATUSCheck(BCryptSecretAgreement(hPrivateKey, hPublicKey, hSecret, 0));
  NTSTATUSCheck(BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nil, nil, 0, @Size, 0));
  SetLength(FPreMasterSecret, Size);
  NTSTATUSCheck(BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nil, PUCHAR(FPreMasterSecret), Size, @Size, 0));
  ReverseArray(FPreMasterSecret);

  NTSTATUSCheck(BCryptDestroySecret(hSecret));
  NTSTATUSCheck(BCryptDestroyKey(hPublicKey));
  NTSTATUSCheck(BCryptDestroyKey(hPrivateKey));
end;

destructor TECDHE_RSAKeyExchange.Destroy;
begin
  NTSTATUSCheck(BCryptCloseAlgorithmProvider(hAlg, 0));
  inherited;
end;

function TECDHE_RSAKeyExchange.ClientKey: TBytes;
begin
  SetLength(Result, 1 + KeySize);
  Result[0] := KeySize;
  if KeySize = 32 then
    Move(ECCPublicKey.PublicKey^, Result[1], 32)
  else begin
    Assert(Cardinal(KeySize) = 1 + 2 * ECCPublicKey.Header.cbKey);
    Result[1] := 4;
    Move(ECCPublicKey.PublicKey^, Result[2], KeySize - 1);
  end;
end;

{ TCustomAESCipher }

procedure TCustomAESCipher.SetMasterSecret(const ClientRandom, ServerRandom: TRandom; const MasterSecret: TBytes; const Hash: IHashAlgorithm);
begin
  Hash.PRF('key expansion', ServerRandom, ClientRandom, MasterSecret, KeyBlock[0], Length(KeyBlock));

  NTSTATUSCheck(BCryptGenerateSymmetricKey(AlgHandle, EncrKeyHandle, nil, 0, EncrKey, KeySize, 0));
  NTSTATUSCheck(BCryptGenerateSymmetricKey(AlgHandle, DecrKeyHandle, nil, 0, DecrKey, KeySize, 0));
end;

{ TAESCipherGCM }

constructor TAESCipherGCM.Create(BitSize: Integer; ServerSide: Boolean = False);
begin
  KeySize := BitSize div 8; // 128 => 16, 256 => 32
  SetLength(KeyBlock, 2 * KeySize + 2 * SizeOf(TEncryptIV));

  if ServerSide then
  begin
    DecrKey := PUCHAR(KeyBlock);
    EncrKey := PUCHAR(@KeyBlock[KeySize]);
    RemoteIV := @KeyBlock[2 * KeySize];
    LocalIV := @KeyBlock[2 * KeySize + SizeOf(TEncryptIV)];
  end else begin
    EncrKey := PUCHAR(KeyBlock);
    DecrKey := PUCHAR(@KeyBlock[KeySize]);
    LocalIV := @KeyBlock[2 * KeySize];
    RemoteIV := @KeyBlock[2 * KeySize + SizeOf(TEncryptIV)];
  end;

  BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
  AuthInfo.pbNonce := @GCMNonce;
  AuthInfo.cbNonce := SizeOf(GCMNonce);
  AuthInfo.pbAuthData := @AESData;
  AuthInfo.cbAuthData := SizeOf(AESData);

  NTSTATUSCheck(BCryptOpenAlgorithmProvider(AlgHandle, BCRYPT_AES_ALGORITHM, nil, 0));
  NTSTATUSCheck(BCryptSetProperty(AlgHandle, BCRYPT_CHAINING_MODE, PUCHAR(BCRYPT_CHAIN_MODE_GCM), (Length(BCRYPT_CHAIN_MODE_GCM) + 1) * SizeOf(Char), 0));

  var BlockLen: DWORD;
  var Len: DWORD := SizeOf(BlockLen);
  NTSTATUSCheck(BCryptGetProperty(AlgHandle, BCRYPT_BLOCK_LENGTH, PUCHAR(@BlockLen), Len, @Len, 0));
end;

function TAESCipherGCM.MaxSize: Cardinal;
begin
  Result := TLS_FRAGMENT_SIZE - SizeOf(TGCMRandom) - SizeOf(TAESTag);
end;

function TAESCipherGCM.EncryptSize(Size: Cardinal): Cardinal;
begin
  Result := SizeOf(TGCMRandom) + Size + SizeOf(TAESTag);
end;

procedure TAESCipherGCM.Decrypt(var APlaintext: PTLSPlaintextHeader);
begin
  Assert(SizeOf(TGCMNonce) = 12);
  Move(RemoteIV^, GCMNonce.IV, SizeOf(GCMNonce.IV));
  var GCMHeader := PGCMHeader(APlaintext.Fragment);
  GCMNonce.Random := GCMHeader.Random;

  var Len: DWORD := APlaintext.Length - SizeOf(GCMHeader.Random) - SizeOf(TAESTag);

  Assert(SizeOf(TAESData) = 13);
  AESData.SeqNum := LLSwap(DecryptSeqNum);
  Inc(DecryptSeqNum);
  AESData.Header := APlaintext^;
  AESData.Header.Length := Len;

  AuthInfo.pbTag := PUCHAR(@GCMHeader.Data[Len]);
  AuthInfo.cbTag := SizeOf(TAESTag);

  Assert(AuthInfo.pbNonce = @GCMNonce);
  Assert(AuthInfo.cbNonce = SizeOf(GCMNonce));
  Assert(AuthInfo.pbAuthData = @AESData);
  Assert(AuthInfo.cbAuthData = SizeOf(AESData));

  NTSTATUSCheck(BCryptDecrypt(
    DecrKeyHandle,
    PUCHAR(@GCMHeader.Data), Len,
    @AuthInfo,
    nil, 0,
    PUCHAR(@Decrypted.Fragment), Len,
    @Len,
    0
  ));

  APlaintext.Length := Len;
  Decrypted.Header := APlaintext^;
  APlaintext := @Decrypted;
end;

procedure TAESCipherGCM.Encrypt(Plaintext: PTLSPlaintextHeader);
begin
  Assert(SizeOf(TGCMNonce) = 12);
  Move(LocalIV^, GCMNonce.IV, SizeOf(GCMNonce.IV));
  FillRandom(GCMNonce.Random, SizeOf(GCMNonce.Random));

  Assert(SizeOf(TAESData) = 13);
  AESData.SeqNum := LLSwap(EncryptSeqNum);
  Inc(EncryptSeqNum);
  AESData.Header := Plaintext^;

  var Encrypted: TBytes;
  SetLength(Encrypted, Plaintext.Length + SizeOf(TAESTag));

  AuthInfo.pbTag := PUCHAR(@Encrypted[Plaintext.Length]);
  AuthInfo.cbTag := SizeOf(TAESTag);

  Assert(AuthInfo.pbNonce = @GCMNonce);
  Assert(AuthInfo.cbNonce = SizeOf(GCMNonce));
  Assert(AuthInfo.pbAuthData = @AESData);
  Assert(AuthInfo.cbAuthData = SizeOf(AESData));

  var Len: ULONG;
  NTSTATUSCheck(BCryptEncrypt(
    EncrKeyHandle,
    PUCHAR(Plaintext.Fragment), Plaintext.Length,
    @AuthInfo,
    nil, 0,
    PUCHAR(Encrypted), Length(Encrypted),
    @Len,
    0
  ));

  Plaintext.Length := SizeOf(TGCMRandom) + Length(Encrypted);
  var GCMHeader := PGCMHeader(Plaintext.Fragment);
  GCMHeader.Random := GCMNonce.Random;
  Move(Encrypted[0], GCMHeader.Data, Length(Encrypted));
end;

{ TAESCipherCBC }

constructor TAESCipherCBC.Create(BitSize: Integer; HashAlgorithm: IHashAlgorithm; ServerSide: Boolean = False);
begin
  HashAlgo := HashAlgorithm;
  HashSize := HashAlgo.HashSize;

  KeySize := BitSize div 8; // 128 => 16, 256 => 32 ...

  IVSize := 16;

  SetLength(KeyBlock, 2 * (HashSize + KeySize + IVSize));

  if ServerSide then
  begin
    DecrHash := @KeyBlock[0];
    EncrHash := @KeyBlock[HashSize];
    DecrKey := PUCHAR(@KeyBlock[2 * HashSize]);
    EncrKey := PUCHAR(@KeyBlock[2 * HashSize + KeySize]);
    RemoteIV := @KeyBlock[2 * (HashSize + KeySize)];
    LocalIV := @KeyBlock[2 * (HashSize + KeySize) + IVSize];
  end else begin
    EncrHash := @KeyBlock[0];
    DecrHash := @KeyBlock[HashSize];
    EncrKey := PUCHAR(@KeyBlock[2 * HashSize]);
    DecrKey := PUCHAR(@KeyBlock[2 * HashSize + KeySize]);
    LocalIV := @KeyBlock[2 * (HashSize + KeySize)];
    RemoteIV := @KeyBlock[2 * (HashSize + KeySize) + IVSize];
  end;

  SetLength(HashKey, HashAlgo.BlockSize);
  SetLength(IV, IVSize);
  SetLength(IV2, IVSize);

  NTSTATUSCheck(BCryptOpenAlgorithmProvider(AlgHandle, BCRYPT_AES_ALGORITHM, nil, 0));
  NTSTATUSCheck(BCryptSetProperty(AlgHandle, BCRYPT_CHAINING_MODE, PUCHAR(BCRYPT_CHAIN_MODE_CBC), (Length(BCRYPT_CHAIN_MODE_CBC) + 1) * SizeOf(Char), 0));
end;

function TAESCipherCBC.MaxSize: Cardinal;
begin
  Result := TLS_FRAGMENT_SIZE - HashSize - 2 * IVSize;
end;

function TAESCipherCBC.EncryptSize(Size: Cardinal): Cardinal;
begin
// Data + Hash
  Result := Size + HashSize;
// IV + (Data + Hash + Padding)
  Result := IVSize + (Result + IVSize - Result mod IVSize);
end;

function TAESCipherCBC.HMAC(Key: PByte; Plaintext: PTLSPlaintextHeader; var SeqNum: UInt64): TBytes;
const
  CInnerPad : Byte = $36;
  COuterPad : Byte = $5C;
begin
  var Seq := LLSwap(SeqNum);
  Inc(SeqNum);

  for var I := 0 to HashSize - 1 do
    HashKey[I] := Key[I] xor CInnerPad;
  FillChar(HashKey[HashSize], Length(HashKey) - Integer(HashSize), CInnerPad);

  HashAlgo.Update(HashKey, Length(HashKey));
  HashAlgo.Update(@Seq, SizeOf(Seq));
  HashAlgo.Update(Plaintext, SizeOf(TTLSPlaintextHeader) + Plaintext.Length);
  var Hash := HashAlgo.Digest;

  for var I := 0 to HashSize - 1 do
    HashKey[I] := Key[I] xor COuterPad;
  FillChar(HashKey[HashSize], Length(HashKey) - Integer(HashSize), COuterPad);
  HashAlgo.Update(HashKey, Length(HashKey));
  HashAlgo.Update(Hash, Length(Hash));

  Result := HashAlgo.Digest;
end;

procedure TAESCipherCBC.Decrypt(var APlaintext: PTLSPlaintextHeader);
begin
  var Len: DWORD := APlaintext.Length;
  if (Len < IVSize) or (Len > TLS_MAX_FRAGMENT) then
    RaiseHandShakeFailure('Fragment overflow');

  Dec(Len, IVSize);

  NTSTATUSCheck(BCryptDecrypt(
    DecrKeyHandle,
    PUCHAR(@PByte(APlaintext.Fragment)[IVSize]), Len,
    nil,
    PUCHAR(APlaintext.Fragment), IVSize,
    PUCHAR(@Plaintext.Fragment), Len,
    @Len,
    0
  ));

// Remove padding
  var Pad := Plaintext.Fragment[Len - 1];
  for var I := 1 to Pad + 1 do
      if Plaintext.Fragment[Len - I] <> Pad then
        RaiseHandShakeFailure('CBC Padding');
  Dec(Len, Pad + 1);

  if Len < HashSize then
    RaiseHandShakeFailure('Padding');
  Dec(Len, HashSize);

  if Len > APlaintext.Length then
    raise ETLSAlert.Create(TAlertLevel.fatal, TAlertDescription.decrypt_error, 'Decrypted size');
  APlaintext.Length := Len;
  Plaintext.Header := APlaintext^;
  APlaintext := @Plaintext;

// Verify Hash
  var LocalHash := HMAC(DecrHash, APlaintext, DecryptSeqNum);
  if not CompareMem(LocalHash, @Plaintext.Fragment[Len], HashSize) then
    RaiseHandShakeFailure('HMAC');
end;

procedure TAESCipherCBC.Encrypt(APlaintext: PTLSPlaintextHeader);
begin
  var Len : DWORD := APlaintext.Length;

// HMAC
  var Hash := HMAC(EncrHash, APlaintext, EncryptSeqNum);
  Assert(Length(Hash) = Integer(HashSize));
  Move(Hash[0], PByte(APlaintext.Fragment)[Len], HashSize);

// Padding
  var xLen := Len + HashSize;
  var PadSize := IVSize - xLen mod IVSize;
  Inc(xLen, PadSize);
  FillChar(PByte(APlaintext.Fragment)[Len + HashSize], PadSize, PadSize - 1);

  var Encrypted: TBytes;
  SetLength(Encrypted, IVSize + xLen);
  FillRandom(IV[0], IVSize);
  Move(IV[0], Encrypted[0], IVSize);

  NTSTATUSCheck(BCryptEncrypt(
    EncrKeyHandle,
    PUCHAR(APlaintext.Fragment), xLen,
    nil,
    PUCHAR(IV), IVSize,
    PUCHAR(@Encrypted[IVSize]), xLen,
    @xLen,
    0
  ));

  APlaintext.Length := Length(Encrypted);
  Move(Encrypted[0], APlaintext.Fragment^, Length(Encrypted));
end;

{ TServerContext }

function TServerContext.CipherAlgorithm: ICipherAlgorithm;
begin
  Result := FCipherAlgorithm;
end;

destructor TServerContext.Destroy;
begin
  if FPubKey <> 0 then
    BCryptDestroyKey(FPubKey);
  if FContext <> nil then
    CertFreeCertificateContext(FContext);
  inherited;
end;

function TServerContext.GetPublicKey(NamedCurve: TCurveName): TBytes;
begin
  FKeyExchangeAlgorithm := TECDHE_RSAKeyExchange.Create(NamedCurve);
  Result := FKeyExchangeAlgorithm.ClientKey;
  Delete(Result, 1, 1); // ?
end;

procedure TServerContext.SetRemoteKey(const Value: TBytes);
begin
  FKeyExchangeAlgorithm.SetRemoteKey(Value);
end;

procedure TServerContext.InitRandom(var Random: TRandom);
begin
  Random.Time := LSwap(System.DateUtils.DateTimeToUnix(System.DateUtils.TTimeZone.Local.ToUniversalTime(Now())));
  FillRandom(Random.Data, SizeOf(Random.Data));
end;

function TServerContext.ClientKeyExchangeAlgorithm: IClientKeyExchangeAlgorithm;
begin
  Result := FKeyExchangeAlgorithm;
end;

procedure TServerContext.ComputeMasterSecret(var ClientRandom,
  ServerRandom: TRandom; var MasterSecret: TBytes);
begin
  FHashAlgorithm.PRF('master secret', ClientRandom, ServerRandom, FKeyExchangeAlgorithm.PreMasterSecret, MasterSecret[0], Length(MasterSecret));
  FCipherAlgorithm.SetMasterSecret(ClientRandom, ServerRandom, MasterSecret, FHashAlgorithm);
end;

procedure TServerContext.ComputeFinished(ALabel: AnsiString; HandShakeData: TMemoryStream; const MasterSecret: TBytes; var Finished: TFinished);
begin
  FHashAlgorithm.PRF(ALabel, FHashAlgorithm.Hash(HandShakeData.Memory, HandShakeData.Size), MasterSecret, Finished, SizeOf(Finished));
end;

function TServerContext.HashAlgorithm: IHashAlgorithm;
begin
  Result := FHashAlgorithm;
end;

function TServerContext.SetCipherSuite(CipherSuite: TCipherSuiteTag): Boolean;
begin
  FCipherSuite := CipherSuite;
  case CipherSuite of
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
    begin
      FHashAlgorithm := TSHA2Hash.Create(256);
      FCipherAlgorithm := TAESCipherGCM.Create(128);
    end;
    TLS_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
    begin
      FHashAlgorithm := TSHA2Hash.Create(384);
      FCipherAlgorithm := TAESCipherGCM.Create(256);
    end;
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
    begin
      FHashAlgorithm := TSHA2Hash.Create(256);
      FCipherAlgorithm := TAESCipherCBC.Create(128, FHashAlgorithm);
    end;
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    begin
      FHashAlgorithm := TSHA2Hash.Create(384);
      FCipherAlgorithm := TAESCipherCBC.Create(256, FHashAlgorithm);
    end;
  else
    Exit(False);
  end;
  Result := True;
end;

procedure TServerContext.VerifyServer(const AHost: UTF8String; const ACertificates: TArray<TBytes>);
const
  USAGES: array[0..2] of PAnsiChar = (
    szOID_PKIX_KP_SERVER_AUTH,
    szOID_SERVER_GATED_CRYPTO,
    szOID_SGC_NETSCAPE
  );
begin
  FContext := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, ACertificates[0], Length(ACertificates[0]));
  if FContext = nil then
    RaiseHandShakeFailure('CertCreateCertificateContext fails to load the certificate');

  Win32Check(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, @FContext.pCertInfo.SubjectPublicKeyInfo, 0, nil, FPubKey));

  case FCipherSuite of
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384:
    begin
      FKeyExchangeAlgorithm := TRSAClientKeyExchange.Create(FPubKey);
    end;
  end;

  var Params: CERT_CHAIN_PARA;
  FillChar(Params, sizeof(Params), 0);
  Params.cbSize := sizeof(Params);
  Params.RequestedUsage.dwType := USAGE_MATCH_TYPE_OR;
  Params.RequestedUsage.Usage.cUsageIdentifier     := Length(USAGES);
  Params.RequestedUsage.Usage.rgpszUsageIdentifier := PAnsiChar(@USAGES);

  var ChainContext: PCCERT_CHAIN_CONTEXT := nil;
  try

    if CertGetCertificateChain(0, FContext, nil, nil, Params, CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, nil, ChainContext) then
    begin
      var Policy: CERT_CHAIN_POLICY_PARA;
      var Status: CERT_CHAIN_POLICY_STATUS;
      var HTTPS : HTTPSPolicyCallbackData;
      var ServerName := string(AHost);

      FillChar(HTTPS, sizeof(HTTPS), 0);
      HTTPS.cbSize := SizeOf(HTTPS);
      HTTPS.dwAuthType := AUTHTYPE_SERVER;
      HTTPS.fdwChecks := 0;
      HTTPS.pwszServerName := PChar(Servername);

      FillChar(Policy, SizeOf(Policy), 0);
      Policy.cbSize := sizeof(Policy);
      Policy.pvExtraPolicyPara := @HTTPS;

      FillChar(Status, SizeOf(Status), 0);
      Status.cbSize := SizeOf(Status);
      if not CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_SSL,
        ChainContext,
        Policy,
        Status
      ) then
      begin
        Status.dwError := TRUST_E_FAIL;

        if Assigned(FOnVerifyServer) then
          FOnVerifyServer(Self, ACertificates, FContext, ChainContext, Status);

        if Status.dwError <> ERROR_SUCCESS then
          raise ECertException.Create('Invalid certificate', Status.dwError);
      end;

    end;
  finally
    if ChainContext <> nil then
      CertFreeCertificateChain(ChainContext);
  end;

end;

procedure TServerContext.VerifySignature(NamedCurve: TCurveName; const PublicKey: TBytes; SignatureScheme: TSignatureScheme; const Digest, Sign: TBytes);
begin
  case FCipherSuite of
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    begin
      FKeyExchangeAlgorithm := TECDHE_RSAKeyExchange.Create(NamedCurve, PublicKey);
    end;
  else
    RaiseHandShakeFailure('KeyExchangeAlgorithm');
  end;

  var PaddingInfo: BCRYPT_PKCS1_PADDING_INFO;
  case SignatureScheme of
    rsa_pkcs1_sha1   : PaddingInfo.psaAligId := 'SHA1';
    rsa_pkcs1_sha256 : PaddingInfo.psaAligId := 'SHA256';
    rsa_pkcs1_sha384 : PaddingInfo.psaAligId := 'SHA384';
  else
    RaiseHandShakeFailure('Signature Algorithm');
  end;
  NTSTATUSCheck(BCryptVerifySignature(FPubKey, @PaddingInfo, PUCHAR(Digest), Length(Digest), PUCHAR(Sign), Length(Sign), BCRYPT_PAD_PKCS1));
end;

end.


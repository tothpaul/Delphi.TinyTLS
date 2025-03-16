unit Execute.TinyTLS;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface
{$IFDEF DEBUG}
{.$DEFINE TLS_LOG}
{.$DEFINE TLS_DEBUG}
{$ENDIF}
uses
  System.Math,
  System.Hash,
  System.SyncObjs,
  System.Classes,
  System.SysUtils,
{$IFDEF TLS_DEBUG}
  Execute.TLS.Debug,
{$ENDIF}
  Execute.Sockets,
  Execute.TinyTLS.Types,
  Execute.TinyTLS.Extensions,
  Execute.TinyTLS.Fragments;

type
  TCertificateRequestEvent = procedure(Sender: TObject; var Certificates: TArray<TBytes>) of object;
  TCertificateVerifyEvent = procedure(Sender: TObject; const Hash: TBytes; var Signature: TBytes) of object;

  TTinyTLS = class(TTLSSocket)
  private
  // Supported Cipher Suites
    FCipherSuites: TArray<TCipherSuiteTag>;
  // Supported Compressions
    FCompressions: TArray<TCompressionMethodTag>;
  // Supported Curves
    FSupportedGroups: TArray<TSupportedGroup>;
  // Supported Signatures
    FSignatures: TArray<TSignatureScheme>;
  // Send Plaintext
    FPlaintext: TTLSPlaintext;
    FHandShake: PHandShakeHeader;
  // Protocol state
    FState: TProtocolState;
  // Hash Algorithm
    FHandShakeData: TMemoryStream;
  // Cipher Algorithms
    FCipherEncode: ICipherAlgorithm;
  // Key Exchange Algorithm
    FCipherDecode: ICipherAlgorithm;
  // Computed Master Secret
    FMasterSecret: TBytes;
  // TLS Session ID
    FSessionID: TBytes;
  // Finish
    FFinish: TFinishedCache;
  // Server public key
    FContext: IServerContext;
  // Client side Random data
    FClientRandom: TRandom;
  // Server side Random data
    FServerRandom: TRandom;
  // Server response is Done
    FServerDone: Boolean;
  // Server Certificates chain list
    FCertificateRequested: Boolean;
    FCertificates: TArray<TBytes>;
    FCertificateTypes: TArray<TClientCertificateType>;
    FSignatureSchemes: TArray<TSignatureScheme>;
    FDistinguishedNames: TArray<UTF8String>;
  // Client Certificate
    FOnCertificateRequest: TCertificateRequestEvent;
    FOnCertificateVerify: TCertificateVerifyEvent;
    procedure DoCertificateRequest(var Certificates: TArray<TBytes>);
    procedure DoCertificateVerify(const Hash: TBytes; var Signature: TBytes);
    procedure Renew;
    procedure SendHandShake;
    procedure ProcessNegociation;
    procedure ClientHello;
    procedure ClientKeyExchange;
    procedure NegociateTLS();
    procedure UpdateDigest(HandShake: PHandShakeHeader);
    procedure ProcessHelloRequest(Payload: PByte; Size: Cardinal);
    procedure ProcessServerHello(Payload: PByte; Size: Cardinal);
    procedure ProcessCertificates(Payload: PByte; Size: Cardinal);
    procedure ProcessServerKeyExchange(Payload: PByte; Size: Cardinal);
    procedure ProcessCertificateRequest(Payload: PByte; Size: Cardinal);
    procedure ProcessServerHelloDone(Payload: PByte; Size: Cardinal);
    procedure ProcessFinished(Payload: PByte; Size: Cardinal);
    procedure ProcessHandShake(Payload: PByte; Size: Cardinal);
    procedure ProcessAlert(Payload: PByte; Size: Cardinal);
    procedure ProcessPlaintext(Plaintext: PTLSPlaintextHeader);
    function DecryptPlaintext(var Plaintext: PTLSPlaintextHeader): Boolean;
    function ReadApplicationData(var Fragment: TTLSFragment): Integer;
    procedure SendPlaintext;
    procedure Encrypt(const Data; Size: Integer);
    procedure Reset;
  public
    constructor Create;
    destructor Destroy; override;
  // TSocket
    function Read(var Data; Size: Integer; Raw: Boolean = False): Integer; override;
    function Write(const Data; Size: Integer; Raw: Boolean = False): Integer; override;
  // TTLSSocket
    procedure StartTLS; override;
  public
    property OnCertificateRequest: TCertificateRequestEvent read FOnCertificateRequest write FOnCertificateRequest;
    property OnCertificateVerify: TCertificateVerifyEvent read FOnCertificateVerify write FOnCertificateVerify;
  end;

implementation

uses
  Execute.TinyTLS.Win.Ciphers;

procedure Burn(var B: TBytes);
begin
  FillChar(PByte(B)^, Length(B), 0);
  B := nil;
end;

{ TTinyTLS }

constructor TTinyTLS.Create;
begin
  inherited;

  Randomize;

  FHandShakeData := TMemoryStream.Create;
  FPlaintext.Header.ProtocolVersion.code := TLS_12;
  FHandShake := FPlaintext.Header.Fragment;

  FCipherSuites := [
//    TLS_RSA_WITH_AES_128_GCM_SHA256,
//    TLS_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  ];

  FCompressions := [Null];

  FSupportedGroups := [
    secp256r1,
    secp384r1,
    x25519
  ];

  FSignatures := [
    TSignatureScheme.ecdsa_sha1,
    TSignatureScheme.rsa_pkcs1_sha1,
    TSignatureScheme.rsa_pkcs1_sha256,
    TSignatureScheme.rsa_pkcs1_sha384
  ];
end;

destructor TTinyTLS.Destroy;
begin
  FHandShakeData.Free;
  inherited;
end;

procedure TTinyTLS.StartTLS;
begin
  Reset;
  NegociateTLS();
end;

procedure TTinyTLS.UpdateDigest(HandShake: PHandShakeHeader);
begin
  if (FHandShakeData <> nil) and (HandShake.HandShakeType <> THandShakeType.HelloRequest) then
    FHandShakeData.Write(HandShake^, SizeOf(THandShakeHeader) + HandShake.Length);
end;

procedure TTinyTLS.ProcessHelloRequest(Payload: PByte; Size: Cardinal);
begin
  if Size > 0 then
    RaiseHandShakeFailure('ServerHello is not empty');
  Renew;
  FState := FState + [psHelloRequest];
end;

procedure TTinyTLS.ProcessServerHello(Payload: PByte; Size: Cardinal);
begin
  FState := FState + [psServerHello];

  if FServerDone or (FCertificates <> nil) then
    RaiseHandShakeFailure('ServerHello out of sync');

  if Size < SizeOf(TServerHello) then
    RaiseOverflow('HelloServer');

  var Hello: PServerHello := PServerHello(Payload);
  if Size < Hello.Length(Size) then
    RaiseOverflow('HelloServer');

  if Hello.Compression <> TCompressionMethodTag.Null then
    RaiseHandShakeFailure('ServerHello compression');

  CheckProtocol(Hello.ProtocolVersion, TLS_12);

  FServerRandom := Hello.Random;

  FSessionID := Hello.SessionID;

  if not FContext.SetCipherSuite(Hello.Cipher) then
    RaiseHandShakeFailure('Unsupported CipherSuite');

{$IFDEF TLS_LOG}DebugSession.CipherSuite := Hello.Cipher;{$ENDIF}

  if Hello.HasExtensions(Size) then
  begin
    var Extensions := Hello.ExtensionList;
    var Index : Cardinal := 0;
    while Index < Extensions.Size do
    begin
      if Index + SizeOf(TExtensionHeader) > Size then
        RaiseOverflow('ServerHello Extensions');
      var Extension := PExtensionHeader(@Extensions.Data[Index]);
      Inc(Index, SizeOf(TExtensionHeader) + Extension.Length);
      if Index > Size then
        RaiseOverflow('ServerHello Extensions');
      case Extension.ExtensionType of
        TExtensionType.RenegotiationInfo:
        begin
          if FFinish.Len = 0 then
          begin
            if (Extension.Length <> 1) or (PRenegotiationInfoExtension(Extension.Payload).Len <> 0) then
              RaiseOverflow('RenegotiationInfo');
          end else begin
            FFinish.Len := 2 * SizeOf(TFinished);
            if (Extension.Length <> SizeOf(FFinish)) or not CompareMem(Extension.Payload, @FFinish, SizeOf(FFinish)) then
              RaiseOverflow('RenegotiationInfo');
          end;
          FFinish.Len := SizeOf(TFinished);
        end;
      end;
    end;
  end;
end;

procedure TTinyTLS.ProcessCertificates(Payload: PByte; Size: Cardinal);
begin
  if FServerDone or (FCertificates <> nil) then
    RaiseHandShakeFailure('Certificates out of sync');
  if Size < SizeOf(TUnsignedInteger24) then
    RaiseOverflow('Certificates overflow');
  var Len: PUnsignedInteger24 := PUnsignedInteger24(Payload);
  if Size <> SizeOf(TUnsignedInteger24) + Len.Value then
    RaiseOverflow('Certificates overflow');

  Dec(Size, SizeOf(TUnsignedInteger24));
  Inc(Payload, SizeOf(TUnsignedInteger24));
  while Size > 0 do
  begin
    if Size < SizeOf(TUnsignedInteger24) then
      RaiseOverflow('Certificate overflow');
    Len := PUnsignedInteger24(Payload);
    var L := Len.Value;
    if Size < SizeOf(TUnsignedInteger24) + L then
      RaiseOverflow('Certificate overflow');
    var B: TBytes;
    SetLength(B, L);
    Inc(Payload, SizeOf(TUnsignedInteger24));
    Dec(Size, SizeOf(TUnsignedInteger24));
    Move(Payload^, B[0], L);
    Inc(Payload, L);
    Dec(Size, L);
    var N := Length(FCertificates);
    SetLength(FCertificates, N + 1);
    FCertificates[N] := B;
  end;

  // Vérification des certificats
  FContext.VerifyServer(Host, FCertificates);
end;

procedure TTinyTLS.ProcessServerKeyExchange(Payload: PByte; Size: Cardinal);
begin
  var ServerKeyExchange: PServerKeyExchange := PServerKeyExchange(Payload);
  ServerKeyExchange.CheckSize(Size);

  if ServerKeyExchange.CurveType <> TCurveType.NamedCurve then
    RaiseHandShakeFailure('Named curve expected');

  var Hash: IHashAlgorithm;
  case ServerKeyExchange.SignatureScheme of
    ecdsa_sha1,
    rsa_pkcs1_sha1   : Hash := TSHA1Hash.Create;
    rsa_pkcs1_sha256 : Hash := TSHA2Hash.Create(256);
    rsa_pkcs1_sha384 : Hash := TSHA2Hash.Create(384);
  else
    RaiseHandShakeFailure('Signature Algorithm');
  end;
  Hash.Update(@FClientRandom, SizeOf(TRandom));
  Hash.Update(@FServerRandom, SizeOf(TRandom));
  Hash.Update(ServerKeyExchange, SizeOf(TServerKeyExchange) + ServerKeyExchange.PublicKeySize);
  var Digest := Hash.Digest;
  var Sign: TBytes := ServerKeyExchange.Signature;

  FContext.VerifySignature(ServerKeyExchange.NamedCurve, ServerKeyExchange.PublicKey, ServerKeyExchange.SignatureScheme, Digest, Sign);
end;

procedure TTinyTLS.ProcessCertificateRequest(Payload: PByte; Size: Cardinal);
begin
  if Size < SizeOf(TCertificateRequest) then
    raise Exception.Create('CertificateRequest overflow');
  var Request := PCertificateRequest(Payload);
  FCertificateTypes := Request.GetCertificateTypes;
  FSignatureSchemes := Request.GetSignatureSchemes;
  FDistinguishedNames := Request.DistinguishedNames;
  FCertificateRequested := True;
end;

procedure TTinyTLS.ProcessServerHelloDone(Payload: PByte; Size: Cardinal);
begin
  FState := FState + [psServerHelloDone];

  if FServerDone or (FCertificates = nil) then
    raise Exception.Create('ServerHelloDone out of sync');

  if Size > 0 then
    RaiseOverflow('ServerHelloDone overflow');

  if FContext.ClientKeyExchangeAlgorithm = nil then
    RaiseHandShakeFailure('KeyExchangeAlgorithm');

  FServerDone := True;
end;

procedure TTinyTLS.ProcessFinished(Payload: PByte; Size: Cardinal);
begin
  if Size <> SizeOf(TFinished) then
    raise Exception.Create('Finished overflow');
  var Finished := PFinished(Payload);

  FContext.ComputeFinished('server finished', FHandShakeData, FMasterSecret, FFinish.Server);
  if not CompareMem(Finished, @FFinish.Server, SizeOf(TFinished)) then
    RaiseHandShakeFailure('Server Finished');

  FActive := True; // TLS Negociation is done !
end;

procedure TTinyTLS.ProcessHandShake(Payload: PByte; Size: Cardinal);
begin
  repeat
    if Size < SizeOf(THandshakeHeader) then
      raise Exception.Create('Handshake overflow');

    var Header: PHandshakeHeader := PHandshakeHeader(Payload);
    var Len := SizeOf(THandshakeHeader) + Header.Length;
    if Size < Len then
      raise Exception.Create('Handshake overflow');
    Inc(Payload, Len);
    Dec(Size, Len);

    case Header.HandShakeType of
      HelloRequest      : ProcessHelloRequest(Header.Payload, Header.Length);
      ServerHello       : ProcessServerHello(Header.Payload, Header.Length);
      Certificate       : ProcessCertificates(Header.Payload, Header.Length);
      ServerKeyExchange : ProcessServerKeyExchange(Header.Payload, Header.Length);
      CertificateRequest: ProcessCertificateRequest(Header.Payload, Header.Length);
      ServerHelloDone   : ProcessServerHelloDone(Header.Payload, Header.Length);
      Finished          : ProcessFinished(Header.Payload, Header.Length);
    else
      raise Exception.Create('Unexpected Handshake');
    end;

    UpdateDigest(Header);
  until Size = 0;
end;

procedure TTinyTLS.ProcessAlert(Payload: PByte; Size: Cardinal);
begin
  if Size < SizeOf(TAlert) then
    raise Exception.Create('Alert overflow');

  var Alert: PAlert := PAlert(Payload);
  var Str: string;
  if (Alert.description = handshake_failure) and (FState = [psClientHello]) then
      Str := 'CiperSuites or SignatureAlgorithms refused by server';

  raise ETLSAlert.Create(Alert, Str);
end;

procedure TTinyTLS.ProcessPlaintext(Plaintext: PTLSPlaintextHeader);
begin
  CheckProtocol(Plaintext.ProtocolVersion, TLS_12);

  if FCipherDecode <> nil then
    FCipherDecode.Decrypt(Plaintext);

{$IFDEF TLS_DEBUG}
  DebugRecv.Debug(Plaintext, SizeOf(TTLSPlaintextHeader) + Plaintext.Length, True);
{$ENDIF}

  var Payload: PByte := Plaintext.Fragment;
  var Len := Plaintext.Length;
  case Plaintext.ContentType of
    HandShake        : ProcessHandShake(Payload, Len);
    ChangeCipherSpec : FCipherDecode := FContext.CipherAlgorithm;
    Alert            : ProcessAlert(Payload, Len);
  else
    RaiseHandShakeFailure('Unexpected Record');
  end;
end;

function TTinyTLS.DecryptPlaintext(var Plaintext: PTLSPlaintextHeader): Boolean;
begin
  CheckProtocol(Plaintext.ProtocolVersion, TLS_12);
  FCipherDecode.Decrypt(Plaintext);

  case Plaintext.ContentType of
    TContentType.ApplicationData: Result := True;
    TContentType.HandShake:
    begin
      if PHandshakeHeader(Plaintext.Fragment).HandShakeType <> THandshakeType.HelloRequest then
        raise Exception.Create('Unexpected Handshake');
      Result := True;
    end;
    TContentType.Alert:
    begin
      Result := False;
      var Alert: PAlert := Plaintext.Fragment;
      case Alert.description of
        close_notify: FActive := False;
      else
        raise Exception.Create('TLS Alert');
      end;
    end
  else
    raise Exception.Create('Expected ApplicationData');
  end;
end;

function TTinyTLS.ReadApplicationData(var Fragment: TTLSFragment): Integer;
begin
  WaitForReader;
  while FReader.Plaintext.ContentType <> TContentType.ApplicationData do
  begin
    try
      ProcessPlaintext(FReader.Plaintext);
    finally
      FReader.Done.SetEvent;
    end;
    WaitForReader;
  end;
  var P := FReader.Plaintext;
  DecryptPlaintext(P);
  Result := P.Length;
  Move(P.Fragment^, Fragment[0], Result);
  FReader.Done.SetEvent;
end;

procedure TTinyTLS.SendPlaintext;
begin
{$IFDEF TLS_DEBUG}
  DebugSend.Debug(@FPlaintext, SizeOf(TTLSPlaintextHeader) + FPlaintext.Header.Length, True);
{$ENDIF}
  if FCipherEncode <> nil then
    FCipherEncode.Encrypt(@FPlaintext);
  WriteAll(FPlaintext, SizeOf(TTLSPlaintextHeader) + FPlaintext.Header.Length, True);
end;

procedure TTinyTLS.Encrypt(const Data; Size: Integer);
begin
  Assert(FCipherEncode <> nil);
  FPlaintext.Header.ContentType := TContentType.ApplicationData;
  var MaxSize := FCipherEncode.MaxSize;
  var P: PByte := @Data;
  while Size > 0 do
  begin
    var L := Min(Size, MaxSize);
    FPlaintext.Header.Length := L;
    Move(P^, FPlaintext.Fragment, L);
    SendPlaintext;
    Inc(P, L);
    Dec(Size, L);
  end;
end;

function TTinyTLS.Read(var Data; Size: Integer; Raw: Boolean): Integer;
begin
  if Raw or not FActive then
    Exit(inherited Read(Data, Size, True));

  while Size > 0 do
  begin

    var Count := Min(Size, FCount);
    if Count > 0 then
    begin
      Move(FData[FStart], Data, Count);
      Dec(FCount, Count);
      if FCount = 0 then
        FStart := 0
      else
        Inc(FStart, Count);
      Exit(Count);
    end;

    FCount := ReadApplicationData(FData);
  end;
  Result := 0;
end;

function TTinyTLS.Write(const Data; Size: Integer; Raw: Boolean): Integer;
begin
  if Raw or not FActive then
    Exit(inherited Write(Data, Size, True));

  Encrypt(Data, Size);
  Result := Size;
end;

procedure TTinyTLS.DoCertificateRequest(var Certificates: TArray<TBytes>);
begin
  if Assigned(FOnCertificateRequest) then
    FOnCertificateRequest(Self, Certificates);
end;

procedure TTinyTLS.DoCertificateVerify(const Hash: TBytes;
  var Signature: TBytes);
begin
  if Assigned(FOnCertificateVerify) then
    FOnCertificateVerify(Self, Hash, Signature);
end;

procedure TTinyTLS.Renew;
begin
  FServerDone := False;
  FCertificates := nil;
  FCertificateTypes := nil;
  FSignatureSchemes := nil;
  FDistinguishedNames := nil;
end;

procedure TTinyTLS.SendHandShake;
begin
  FPlaintext.Header.ContentType := TContentType.HandShake;
  FPlaintext.Header.Length := SizeOf(THandshakeHeader) + FHandShake.Length;
  UpdateDigest(FHandShake);
  SendPlaintext;
end;

procedure TTinyTLS.ProcessNegociation;
begin
  WaitForReader;
  ProcessPlaintext(FReader.Plaintext);
  FReader.Done.SetEvent;
end;

procedure TTinyTLS.ClientHello;
begin
  FActive := False;
  FServerDone := False;
  FCertificateRequested := False;
  FHandShakeData.Clear;
// https://tls12.xargs.org/#client-hello/annotated
  FContext.InitRandom(FClientRandom);

  Assert(SizeOf(TCipherSuiteTag) = 2);
  Assert(SizeOf(TCompressionMethodTag) = 1);
  Assert(FHandShake = FPlaintext.Header.Fragment);

  var Hello: PClientHello := FHandShake.Payload;
  Hello.ProtocolVersion.code := TLS_12;
  Hello.Random := FClientRandom;
  Hello.SessionIDLen := 0;

  Hello.CipherList.SetCiphers(FCipherSuites);
  Hello.CompressionList.SetCompressions(FCompressions);

  var ExtensionList := Hello.ExtensionList;
  var ExtIndex: Integer := 0;

  var Extension := ExtensionList.Items[ExtIndex];
  Extension.ExtensionType := ServerName;
  Extension.Length := TServerNameExtension.SizeFor(Host);
  PServerNameExtension(Extension.Payload).Name := Host;
  Inc(ExtIndex);

  if Length(FSupportedGroups) > 0 then
  begin
    Extension := ExtensionList.Items[ExtIndex];
    Extension.ExtensionType := TExtensionType.SupportedGroups;
    Extension.Length := PSupportedGroupsExtension(Extension.Payload).SetGroups(FSupportedGroups);
    Inc(ExtIndex);
  end;

  // Accept only uncompressed information from the server.
  Extension := ExtensionList.Items[ExtIndex];
  Extension.ExtensionType := TExtensionType.ECPointFormats;
  Extension.Length := PECPointFormatsExtension(Extension.Payload).SetFormats([uncompressed]);
  Inc(ExtIndex);

  if Length(FSignatures) > 0 then
  begin
    Extension := ExtensionList.Items[ExtIndex];
    Extension.ExtensionType := TExtensionType.SignatureAlgorithms;
    Extension.Length := PSignatureAlgorithmsExtension(Extension.Payload).SetSignatureSchemes(FSignatures);
    Inc(ExtIndex);
  end;

//  Extension := ExtensionList.Items[ExtIndex];
//  Extension.ExtensionType := TExtensionType.SessionTicketTLS;
//  Extension.Length := 0;
//  Inc(ExtIndex);
//
//  Extension := ExtensionList.Items[ExtIndex];
//  Extension.ExtensionType := TExtensionType.ExtendedMasterSecret;
//  Extension.Length := 0;
//  Inc(ExtIndex);

  Extension := ExtensionList.Items[ExtIndex];
  Extension.ExtensionType := RenegotiationInfo;
  Extension.Length := 1 + FFinish.Len;
  Assert(
    (FFinish.Len = 0) // no encryption, or no serveur extension
  or
    ((FCipherEncode <> nil) and (FFinish.Len = SizeOf(TFinished)))
  );
  Move(FFinish, Extension.Payload^, 1 + FFinish.Len);
  Inc(ExtIndex);

  ExtensionList.Size := ExtensionList.ItemOffset(ExtIndex);

  FHandShake.HandShakeType := THandShakeType.ClientHello;
  FHandShake.Length := SizeOf(TClientHello)
                     + TCipherList.SizeFor(FCipherSuites)
                     + TCompressionList.SizeFor(FCompressions)
                     + TExtensionList.SizeFor(ExtensionList.Size);

  FState := FState + [psClientHello];

  SendHandShake;
end;

procedure TTinyTLS.ClientKeyExchange;
begin
// Certificate
  if FCertificateRequested then
  begin
    var Cert: TArray<TBytes>;
    DoCertificateRequest(Cert);
    var Size := 0;
    for var I := 0 to Length(Cert) - 1 do
      Inc(Size, SizeOf(TUnsignedInteger24) + Length(Cert[I]));
    FHandShake.HandShakeType := THandShakeType.Certificate;
    FHandShake.Length := SizeOf(TUnsignedInteger24) + Size;
    var PSize: PUnsignedInteger24 := FHandShake.Payload;
    PSize.Value := Size;
    Inc(PSize);
    for var I := 0 to Length(Cert) - 1 do
    begin
      PSize.Value := Length(Cert[I]);
      Inc(PSize);
      Move(Cert[I][0], PSize^, Length(Cert[I]));
      Inc(PByte(PSize), Length(Cert[I]));
    end;
    SendHandShake;
  end;

// ClientKeyExchange
  var ClientKey := FContext.ClientKeyExchangeAlgorithm.ClientKey;
  FHandShake.HandShakeType := THandShakeType.ClientKeyExchange;
  FHandShake.Length := Length(ClientKey);
  Move(ClientKey[0], FHandShake.Payload^, Length(ClientKey));
  SendHandShake;

// CertificateVerify
  if FCertificateRequested then
  begin
    var Hash := THashSHA1.Create;
    Hash.Update(FHandShakeData.Memory^, FHandShakeData.Size);
    var Digest := Hash.HashAsBytes;
    var Sign: TBytes;
    DoCertificateVerify(Digest, Sign);
    if Length(Sign) = 256 then
    begin
      FHandShake.HandShakeType := THandShakeType.CertificateVerify;
      FHandShake.Length := SizeOf(TCertificateVerify);
      var Verify := PCertificateVerify(FHandShake.Payload);
      Verify.Algorithm.Hash := THashAlgorithm.sha1;
      Verify.Algorithm.Signature := TSignatureAlgorithm.rsa;
      Verify.Size := 256;
      Move(Sign[0], Verify.Signature, 256);
      SendHandShake;
    end;
  end;

// ChangeCipherSpec
  FPlaintext.Header.ContentType := TContentType.ChangeCipherSpec;
  FPlaintext.Header.Length := 1;
  FPlaintext.Fragment[0] := 1;
  SendPlaintext;

// Finished
{$IFDEF TLS_DEBUG}DebugSession.SetPreMasterSecret(FContext.ClientKeyExchangeAlgorithm.PreMasterSecret);{$ENDIF}
  SetLength(FMasterSecret, SizeOf(TMasterSecret));
  FContext.ComputeMasterSecret(FClientRandom, FServerRandom, FMasterSecret);
  FContext.ComputeFinished('client finished', FHandShakeData, FMasterSecret, FFinish.Client);

  FHandShake.HandShakeType := THandShakeType.Finished;
  FHandShake.Length := SizeOf(TFinished);
  Move(FFinish.Client, FHandShake.Payload^, SizeOf(TFinished));

  FCipherEncode := FContext.CipherAlgorithm;
  SendHandShake;
end;

procedure TTinyTLS.NegociateTLS();
begin
  FReader := TTLSReader.Create(Self);

  ClientHello;

  repeat
    ProcessNegociation;
  until FServerDone;

  ClientKeyExchange;

  repeat
    ProcessNegociation
  until Active;
end;

procedure TTinyTLS.Reset;
begin
  FState := [];
  FActive := False;
  FHandShakeData.Clear;
  FCipherEncode := nil;
  FCipherDecode := nil;
  Burn(FMasterSecret);
  FSessionID := nil;
  FillChar(FFinish, SizeOf(FFinish), 0);
  // the only link to Execute.TinyTSL.Win.Ciphers
  FContext := TServerContext.Create();
  Renew;
end;

end.

unit Execute.SChannel;

{
  SChannel TLS Socket (c)2025 Execute SARL
}

interface
{.$DEFINE TLS_DEBUG}
uses
  System.SysUtils,
  System.Math,
  Winapi.Windows,
{$IFDEF TLS_DEBUG}
  Execute.TLS.Debug,
{$ENDIF}
  Execute.Sockets,
  Execute.TinyTLS.Types,
  Execute.WinSSPI;

type
  ESChannel = class(Exception)
  end;

  ESChannelError = class(ESChannel)
    Error: SECURITY_STATUS;
    constructor Create(Error: SECURITY_STATUS; const Msg: string);
  end;

  TSSLInit = set of (iCredentials, iContext);

  TAuthData = record
  case Boolean of
    False: (OLD: SCHANNEL_CRED);
    True : (NEW: SCH_CREDENTIALS);
  end;

  TSChannel = class(TTLSSocket)
  private
    class var Secur32: THandle;
    class var InitSecurityInterface: function: PSecurityFunctionTable; stdcall;
    class var SSPI: PSecurityFunctionTable;
    class var MyStore: HCERTSTORE;
    class constructor Create;
  private
    FInit: TSSLInit;
    FCredentials: TCredHandle;
    FContext: TCtxtHandle;
    FErrNo: HRESULT;
    FBuffSizes: TSecPkgContextStreamSizes;
    FSendBuffer: TBytes;
    procedure SendSecBuffer(var Buffer: TSecBuffer);
    procedure NegociateTLS();
    procedure VerifyServer();
    procedure ProcessPlaintext(Plaintext: PTLSPlaintextHeader);
    function DecryptPlaintext(var Plaintext: PTLSPlaintextHeader; var Fragment: TTLSFragment): Integer;
    function ReadApplicationData(var Fragment: TTLSFragment): Integer;
    procedure Encrypt(const Data; Size: Integer);
  public
  // TSocket
    function Read(var Data; Size: Integer; Raw: Boolean = False): Integer; override;
    function Write(const Data; Size: Integer; Raw: Boolean = False): Integer; override;
  // TTLSSocket
    procedure StartTLS; override;
  end;

implementation


{ ESChannelError }

constructor ESChannelError.Create(Error: SECURITY_STATUS; const Msg: string);
begin
  Self.Error := Error;
  inherited Create(Msg + ' 0x' + IntToHex(Error));
end;

{ TSChanel }

class constructor TSChannel.Create;
begin
  Secur32 := LoadLibrary('SECUR32.DLL');
  @InitSecurityInterface := GetProcAddress(Secur32, 'InitSecurityInterfaceW');
  if @InitSecurityInterface <> nil then
  begin
    SSPI := InitSecurityInterface();
    if SSPI <> nil then
      MyStore := CertOpenSystemStore(0, 'MY');
  end;
end;

procedure TSChannel.SendSecBuffer(var Buffer: TSecBuffer);
begin
  if (Buffer.cbBuffer > 0) and (Buffer.pvBuffer <> nil) then
  begin
  {$IFDEF TLS_DEBUG}
    DebugSend.Debug(Buffer.pvBuffer, Buffer.cbBuffer, not FActive);
  {$ENDIF}
    if not WriteAll(buffer.pvBuffer^, Buffer.cbBuffer, True) then
      raise ESChannel.Create('SendSecBuffer');
    if Buffer.BufferType = SECBUFFER_TOKEN then
    begin
      SSPI.FreeContextBuffer(Buffer.pvBuffer);
      Buffer.pvBuffer := nil;
      Buffer.cbBuffer := 0;
    end;
  end;
end;

procedure TSChannel.StartTLS;
begin
  if SSPI = nil then
    raise ESChannel.Create('SChannel is not available');

  var Auth: TAuthData;
  FillChar(Auth, SizeOf(Auth), 0);

  if TOSVersion.Build < 17763 then  // Windows 10 - 1809
  begin
  // fail with error SEC_E_ALGORITHM_MISMATCH if you specify TLS 1.3
  // https://learn.microsoft.com/en-us/answers/questions/708734/tls-1-3-doesnt-work-on-windows-11-through-schannel
    Auth.OLD.dwVersion := SCHANNEL_CRED_VERSION;
    Auth.OLD.grbitEnabledProtocols := SP_PROT_TLS1_2 or SP_PROT_TLS1_3;
    Auth.OLD.dwFlags := SCH_CRED_NO_DEFAULT_CREDS or SCH_CRED_MANUAL_CRED_VALIDATION or SCH_USE_STRONG_CRYPTO;
  end else begin
  // should work for TLS 1.3 under Windows 11
    Auth.NEW.dwVersion := SCH_CREDENTIALS_VERSION;
    Auth.NEW.dwFlags := SCH_CRED_NO_DEFAULT_CREDS or SCH_CRED_MANUAL_CRED_VALIDATION or SCH_USE_STRONG_CRYPTO;
  end;

  FillChar(FCredentials, SizeOf(FCredentials), 0);
  FillChar(FContext, SizeOf(FContext), 0);

  FErrNo := SSPI.AcquireCredentialsHandle(
    nil,
    UNISP_NAME,
    SECPKG_CRED_OUTBOUND,
    nil,
   @Auth,
    nil,
    nil,
   @FCredentials,
   nil
  );
  if FErrNo <> SEC_E_OK then
    raise ESChannelError.Create(FErrNo, 'AcquireCredentialsHandle');

  FInit := [iCredentials];

  FReader := TTLSReader.Create(Self);

  NegociateTLS();

  VerifyServer();
end;

procedure TSChannel.VerifyServer;
const
  USAGES: array[0..2] of PAnsiChar = (
    szOID_PKIX_KP_SERVER_AUTH,
    szOID_SERVER_GATED_CRYPTO,
    szOID_SGC_NETSCAPE
  );
var
  Server: PCCERT_CONTEXT;
  ChainPara: CERT_CHAIN_PARA;
  Chain : PCCERT_CHAIN_CONTEXT;
  HTTPS : HTTPSPolicyCallbackData;
  Policy: CERT_CHAIN_POLICY_PARA;
  Status: CERT_CHAIN_POLICY_STATUS;
begin
  Server := nil;
  FErrNo := SSPI.QueryContextAttributes(@FContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, @Server);
  if FErrNo <> 0 then
    raise ESChannelError.Create(FErrNo, 'QueryCredentialsAttributes');
  try
    FillChar(ChainPara, sizeof(ChainPara), 0);
    ChainPara.cbSize := sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier     := Length(USAGES);
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := PAnsiChar(@USAGES);

    if not CertGetCertificateChain(
      0,
      Server,
      nil,
      Server.hCertStore,
      ChainPara,
      0,
      nil,
      Chain
    ) then
      raise ESChannelError.Create(GetLastError, 'CertGetCertificateChain');
    try
      var ServerName := string(Host);

      FillChar(HTTPS, sizeof(HTTPS), 0);
      HTTPS.cbSize := SizeOf(HTTPS);
      HTTPS.dwAuthType := AUTHTYPE_SERVER;
      HTTPS.fdwChecks := 0;
      HTTPS.pwszServerName := PChar(ServerName);

      FillChar(Policy, SizeOf(Policy), 0);
      Policy.cbSize := sizeof(Policy);
      Policy.pvExtraPolicyPara := @HTTPS;

      FillChar(Status, SizeOf(Status), 0);
      Status.cbSize := SizeOf(Status);

      if not CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_SSL,
        Chain,
        Policy,
        Status
      ) then
        raise ESChannelError.Create(GetLastError, 'CertVerifyCertificateChainPolicy');

//      if Status.dwError = CERT_E_UNTRUSTEDROOT then
//        Validate(Chain, Status);

      if Status.dwError <> 0 then
        raise ESChannelError.Create(Status.dwError, 'CertVerifyCertificateChainPolicy');

    finally
      CertFreeCertificateChain(Chain);
    end;
  finally
    CertFreeCertificateContext(Server);
  end;
end;

procedure TSChannel.NegociateTLS;
var
  Ctx1, Ctx2: PCtxtHandle;
  Flags: DWORD;
  OutBuffer : TSecBufferDesc;
  OutBuffers: array[0..0] of TSecBuffer;
begin
  if iContext in FInit then
  begin
  // SEC_I_RENEGOTIATE, use the current context
    Ctx1 := @FContext;
    Ctx2 := nil;
  end else begin
  // create a new context
    Ctx1 := nil;
    Ctx2 := @FContext;
  end;

  var HostName := string(Host);

  // Initiate a ClientHello Message
  OutBuffer.ulVersion := SECBUFFER_VERSION;
  OutBuffer.cBuffers := 1;
  OutBuffer.pBuffers := Addr(OutBuffers[0]);

  OutBuffers[0].cbBuffer := 0;
  OutBuffers[0].BufferType := SECBUFFER_TOKEN;
  OutBuffers[0].pvBuffer := nil;

  FErrNo := SSPI.InitializeSecurityContext(
   @FCredentials,
    Ctx1,   // nil on first call, to create the Context
    PChar(HostName),
    ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or ISC_REQ_CONFIDENTIALITY
    or ISC_RET_EXTENDED_ERROR or ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_STREAM,
    0,
    SECURITY_NATIVE_DREP,
    nil,
    0,
    Ctx2,
   @OutBuffer,
    Flags,
    nil
  );

  if FErrNo = SEC_E_OK then
    Exit;   // when SEC_I_RENEGOTIATE succeed directly

  if (FErrNo <> SEC_I_CONTINUE_NEEDED) then
    raise ESChannelError.Create(FErrNo, 'InitializeSecurityContext');

  FInit := FInit + [iContext];

  // Send Client Hello
  SendSecBuffer(OutBuffers[0]);

  repeat
    WaitForReader;
    ProcessPlaintext(FReader.Plaintext);
    FReader.Done.SetEvent;
  until FErrNo <> SEC_I_CONTINUE_NEEDED;

  if FErrNo <> SEC_E_OK then
    raise ESChannelError.Create(FErrNo, 'NegociateTLS');

  FActive := True;
end;

procedure TSChannel.ProcessPlaintext(Plaintext: PTLSPlaintextHeader);
var
  InBuffers : array[0..1] of TSecBuffer;
  InBuffer  : TSecBufferDesc;
  OutBuffers: array[0..0] of TSecBuffer;
  OutBuffer : TSecBufferDesc;
  Flags     : DWORD;
begin
{$IFDEF TLS_DEBUG}
  DebugRecv.Debug(Plaintext, SizeOf(TTLSPlaintextHeader) + Plaintext.Length, FActive = False);
{$ENDIF}

  // input data
  InBuffer.ulVersion := SECBUFFER_VERSION;
  InBuffer.cBuffers := 2;
  inBuffer.pBuffers := Addr(InBuffers[0]);

  // output data
  OutBuffer.ulVersion := SECBUFFER_VERSION;
  OutBuffer.cBuffers := 1;
  OutBuffer.pBuffers := Addr(OutBuffers[0]);

  // available input data
  InBuffers[0].cbBuffer := SizeOf(TTLSPlaintextHeader) + Plaintext.Length;
  InBuffers[0].BufferType := SECBUFFER_TOKEN;
  InBuffers[0].pvBuffer := Plaintext;

  // used when there's extra data in the input buffer
  InBuffers[1].cbBuffer := 0;
  InBuffers[1].BufferType := SECBUFFER_EMPTY;
  InBuffers[1].pvBuffer := nil;

  // output data
  OutBuffers[0].cbBuffer := 0;
  OutBuffers[0].BufferType := SECBUFFER_TOKEN;
  OutBuffers[0].pvBuffer := nil;

  FErrNo := SSPI.InitializeSecurityContext(
   @FCredentials,
   @FContext,
    nil,
    ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or ISC_REQ_CONFIDENTIALITY
    or ISC_RET_EXTENDED_ERROR or ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_STREAM,
    0,
    SECURITY_NATIVE_DREP,
   @InBuffer,
    0,
    nil,
   @OutBuffer,
    Flags,
    nil
  );

  SendSecBuffer(OutBuffers[0]);

  // SEC_I_RENEGOTIATE => NegociateTLS() - need a test case for that

  if (FErrNo <> 0) and (Plaintext.ContentType = TContentType.Alert) and (Plaintext.Length = SizeOf(TAlert)) then
  begin
    raise ETLSAlert.Create(PAlert(Plaintext.Fragment), 'InitializeSecurityContext = 0x' + IntToHex(FErrNo));
  end;

end;

function TSChannel.DecryptPlaintext(var Plaintext: PTLSPlaintextHeader; var Fragment: TTLSFragment): Integer;
var
  Buffers: array[0..3] of TSecBuffer;
  Buffer : TSecBufferDesc;
begin
{$IFDEF TLS_DEBUG}
  DebugRecv.Debug(Plaintext, SizeOf(TTLSPlaintextHeader) + Plaintext.Length, True);
{$ENDIF}
  FillChar(Buffers, SizeOf(Buffers), 0);
  Buffers[0].cbBuffer := SizeOf(TTLSPlaintextHeader) + Plaintext.Length;
  Buffers[0].BufferType := SECBUFFER_DATA;
  Buffers[0].pvBuffer := Plaintext;

  Buffer.ulVersion := SECBUFFER_VERSION;
  Buffer.cBuffers := 4; // Required to avoid error 0x80090308 !
  Buffer.pBuffers := Addr(Buffers[0]);

  FErrNo := SSPI.DecryptMessage(@FContext, @Buffer, 0, nil);

  if FErrNo = SEC_I_RENEGOTIATE then  // occurs with TLS 1.3 for instance
  begin
    NegociateTLS();
    Exit(0);
  end;

  if FErrNo <> SEC_E_OK then
    raise ESChannelError.Create(FErrno, 'DecryptMessage');

  // Buffer[0] = HEADER
  // Buffer[1] = DATA
  // Buffer[2] = FOOTER
  // Buffer[3] = EMPTY
  Result := 0;
  for var I := 1 to 3 do
  begin
    if (Buffers[I].BufferType = SECBUFFER_DATA) and (Buffers[I].cbBuffer > 0) then
    begin
      Move(Buffers[I].pvBuffer^, Fragment[Result], Buffers[I].cbBuffer);
      Inc(Result, Buffers[1].cbBuffer);
    end;
  end;
end;

procedure TSChannel.Encrypt(const Data; Size: Integer);
var
  Source : PByte;
  Index  : Integer;
  Count  : Integer;
  Buffers: array[0..3] of TSecBuffer;
  Buffer : TSecBufferDesc;
begin
  if FBuffSizes.cbMaximumMessage = 0 then
  begin
    FErrNo := SSPI.QueryContextAttributes(@FContext, SECPKG_ATTR_STREAM_SIZES, @FBuffSizes);
    if FErrNo <> SEC_E_OK then
      raise ESChannelError.Create(FErrNo, 'QueryContextAttributes');
    SetLength(FSendBuffer, FBuffSizes.cbHeader + {$IFDEF TLS_DEBUG}FBuffSizes.cbMaximumMessage +{$ENDIF} FBuffSizes.cbTrailer);
  end;
  Source := @Data;
  Index := 0;
  while Size > 0 do
  begin
    if Cardinal(Size) > FBuffSizes.cbMaximumMessage then
      Count := FBuffSizes.cbMaximumMessage
    else
      Count := Size;

  {$IFDEF TLS_DEBUG}
  // need a single buffer for DebugSend.Debug()
    Move(Source^, FSendBuffer[FBuffSizes.cbHeader], Count);
  {$ENDIF}

    Buffers[0].cbBuffer := FBuffSizes.cbHeader;
    Buffers[0].BufferType := SECBUFFER_STREAM_HEADER;
    Buffers[0].pvBuffer := @FSendBuffer[0];

    Buffers[1].cbBuffer := Count;
    Buffers[1].BufferType := SECBUFFER_DATA;
    Buffers[1].pvBuffer := {$IFDEF TLS_DEBUG}@FSendBuffer[FBuffSizes.cbHeader]{$ELSE}Source{$ENDIF};

    Buffers[2].cbBuffer := FBuffSizes.cbTrailer;
    Buffers[2].BufferType := SECBUFFER_STREAM_TRAILER;
    Buffers[2].pvBuffer := @FSendBuffer[FBuffSizes.cbHeader {$IFDEF TLS_DEBUG}+ Count{$ENDIF}];

    Buffers[3].BufferType := SECBUFFER_EMPTY;

    Buffer.ulVersion := SECBUFFER_VERSION;
    Buffer.cBuffers := 4;
    Buffer.pBuffers := Addr(Buffers[0]);

    FErrNo := SSPI.EncryptMessage(@FContext, 0, @Buffer, 0);

    if FErrNo <> SEC_E_OK then
      raise ESChannelError.Create(FErrNo, 'EncryptMessage');

  {$IFDEF TLS_DEBUG}
     DebugSend.Debug(FSendBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, False);
    if not WriteAll(FSendBuffer[0], Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, True) then
      raise ESChannel.Create('Write error');
  {$ELSE}
    SendSecBuffer(Buffers[0]);
    SendSecBuffer(Buffers[1]);
    SendSecBuffer(Buffers[2]);
  {$ENDIF}
    Inc(Source, Count);
    Dec(Size, Count);
  end;
end;

function TSChannel.Read(var Data; Size: Integer; Raw: Boolean): Integer;
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

function TSChannel.ReadApplicationData(var Fragment: TTLSFragment): Integer;
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
  Result := DecryptPlaintext(P, Fragment);
  FReader.Done.SetEvent;
end;

function TSChannel.Write(const Data; Size: Integer; Raw: Boolean): Integer;
begin
  if Raw or not FActive then
    Exit(inherited Write(Data, Size, True));
  Encrypt(Data, Size);
  Result := Size;
end;

end.

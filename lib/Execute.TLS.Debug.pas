unit Execute.TLS.Debug;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

// https://www.acunetix.com/blog/articles/establishing-tls-ssl-connection-part-5/
// https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/
// https://www.ipa.go.jp/security/rfc/RFC4346EN.html#062
// https://serializethoughts.com/2014/07/27/dissecting-tls-client-hello-message/

interface
{$WARN SYMBOL_PLATFORM OFF}
uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.DateUtils,
  System.Hash,
  System.IOUtils,
  Execute.Crypto,
  Execute.Winapi.BCrypt,
  Execute.TinyTLS.Types,
  Execute.TinyTLS.Extensions,
  Execute.TinyTLS.Fragments,
  Execute.TinyTLS.Win.Ciphers;

const
  ProtocolDebug = True;
  AdvancedDebug = True;

  SHA1_OID: TBytes = [
    $30, 33,                // SEQUENCE of 33 (11 + 22) bytes
      $30, 9,               //   SEQUENCE of 9 (7 + 2) bytes (11 bytes)
        $06,5,40*1+3,14,3,2,26, //     OID of 5 Bytes => 1.3.14.3.2.26 (SHA1) (7 bytes)
        $05, 0,             //     NULL (2 bytes)
      $04, 20 {, Data }     //   OCTET_STRING of 20 Bytes (22 bytes)
  ];

  SHA256_OID: TBytes = [
    $30, 49,                 // SEQUENCE of 49 (15 + 34) bytes
      $30, 13,               //   SEQUENCE of 13 (11 + 2) bytes (15 bytes)
        $06, 9, 40 * 2 + 16, $80 + 840 shr 7, 840 and $7F, 1, 101, 3, 4, 2, 1, //  OID of 9 Bytes => 2.16.840.1.101.3.4.2.1 (SHA256) (11 bytes)
        $05, 0,              //     NULL (2 bytes)
      $04 ,32 {, Data }      //   OCTET_STRING of 32 Bytes (34 bytes)
  ];

  SHA384_OID: TBytes = [
    $30, 65,                 // SEQUENCE of 65 (15 + 50) bytes
      $30, 13,               //   SEQUENCE of 13 (11 + 2) bytes (15 bytes)
        $06, 9, 40 * 2 + 16, $80 + 840 shr 7, 840 and $7F, 1, 101, 3, 4, 2, 2, //  OID of 9 Bytes => 2.16.840.1.101.3.4.2.2 (SHA384) (11 bytes)
        $05, 0,              //     NULL (2 bytes)
      $04 ,48 {, Data }      //   OCTET_STRING of 48 Bytes (50 bytes)
  ];

type
  TLogProc = procedure(const Msg: string) of object;

  TTLSPlaintextHolder = record
    Header: PTLSPlaintextHeader;
    Size  : Integer;
    Data  : PByte;
    function GetHandShake: PHandShakeHeader;
    function GetAlert: PAlert;
    function GetApplicationData: AnsiString;
    function Load(AData: Pointer; ASize: Integer): Boolean;
  end;

  TDebugTLS = class
  private
    FName   : string;
    FIter   : Integer;
    FLogProc: TLogProc;
    FSrcByte: PByte;
    FSrcLen : Integer;
    FSrcPad : string;
    FPublicKey: TRSAPublicKey;
    FChangeCipherSpec: Boolean;
    procedure Log(const Msg: string);
    procedure DebugDERSequence(Tag: Byte; Len: Integer);
    procedure DebugDERInteger(Tag: Byte; Len: Integer);
    procedure DebugDEROID(Tag: Byte; Len: Integer);
    function ReadOID(Len: Integer): string;
    procedure DebugDERUTF8String(Tag: Byte; Len: Integer);
    procedure DebugDERAnsiString(Tag: Byte; Len: Integer);
    procedure DebugDERTime(Tag: Byte; Len: Integer);
    procedure DebugDER;
    procedure DebugCA;
    function ReadCA: string;
    procedure DebugRandom(const Random: TRandom);
    procedure DebugSessionID(const ID: TBytes);
    procedure DebugCipherSuites(const Suites: PCipherList);
    procedure DebugCompressionMethods(const Compressions: PCompressionList);
    procedure DebugServerName(Extension: PExtensionHeader);
    procedure DebugSupportedGroups(Extension: PExtensionHeader);
    procedure DebugECPointFormats(Extension: PExtensionHeader);
    procedure DebugSignatureAlgorithms(Extension: PExtensionHeader);
    procedure DebugSupportedVersions(Extension: PExtensionHeader; Client: Boolean);
    procedure DebugPSKeyExchangeModes(Extension: PExtensionHeader);
    procedure DebugKeyShare(Extension: PExtensionHeader; Client: Boolean);
    procedure DebugExtension(Extension: PExtensionHeader; Client: Boolean);
    function DebugExtensions(ExtensionList: PExtensionList; Client: Boolean): Word;
    procedure DebugHelloRequest(HandShake: PHandShakeHeader);
    procedure DebugClientHello(HandShake: PHandShakeHeader);
    procedure DebugServerHello(HandShake: PHandShakeHeader);
    procedure DebugNewSessionTicket(HandShake: PHandShakeHeader);
    procedure DebugFinished(HandShake: PHandShakeHeader);
    procedure DebugCertificate;
    procedure DebugCertificates(HandShake: PHandShakeHeader);
    procedure DebugPubKey;
    procedure DebugServerKeyExchange(HandShake: PHandShakeHeader);
    procedure DebugClientKeyExchange(HandShake: PHandShakeHeader);
    procedure DebugCertificateRequest(HandShake: PHandShakeHeader);
    procedure DebugCertificateVerify(HandShake: PHandShakeHeader);
    procedure DebugChangeCipherSpec(var TLSRecord: TTLSPlaintextHolder);
    procedure DebugHandShakes(var TLSRecord: TTLSPlaintextHolder);
    procedure DebugAlert(var TLSRecord: TTLSPlaintextHolder);
    procedure DebugApplicationData(var TLSRecord: TTLSPlaintextHolder);
    function BeginIter(const Title: string; Size: Integer = -1): Integer;
    procedure EndIter(Save: Integer = -1);
    procedure DumpSrc(const Title: string; Size: Integer);
    procedure BlockRead(var Data; Size: Integer);
    function GetByte: Byte;
    function GetWord: Word;
    function GetVariableLen: Integer;
    procedure DebugTLSRecord(var TLSRecord: TTLSPlaintextHolder; Uncrypted: Boolean = False);
    procedure TraceHandShakes;
  public
    constructor Create(const AName: string);
    function Debug(Data: Pointer; Len: Integer; Uncrypted: Boolean = False): Integer;
    procedure DebugType(Data: Pointer; Len: Integer; ContentType: TContentType);
    procedure DebugHandShake(HandShake: PHandShakeHeader);
    procedure DebugDigest(Data: TMemoryStream);
    procedure Consume(Stream: TMemoryStream);
    procedure Dump(Data: Pointer; Size: Integer);
    procedure DumpVar(const Title: string; Data: Pointer; Size: Integer);
    property LogProc: TLogProc read FLogProc write FLogProc;
  end;

  TDebugTLSSession = class(TDebugTLS)
  private
    FFile: TextFile;
    FCertCount: Integer;
    FHandShakes: Integer;
    FHandShakeData: TMemoryStream;
    FCipherSuite: TCipherSuiteTag;
    FHashAlgorithm: IHashAlgorithm;
    FClientRandom: TRandom;
    FServerRandom: TRandom;
    FPreMasterSecret: TBytes;
    FMasterSecret: TBytes;
    FKeyBlock: TBytes;
    FFinished: TBytes;
    FSave: TFileStream;
    procedure DoLog(const Str: string);
    procedure SetCipherSuite(Value: TCipherSuiteTag);
  public
    constructor Create(const AName: string);
    destructor Destroy; override;
    procedure DumpConst(const Name: string; Data: Pointer; Size: Integer);
    procedure UpdateDigest(HandShake: PHandShakeHeader);
    procedure ClearHash;
    function DigestSHA1: TBytes;
    function DigestSHA256: TBytes;
    function DigestSHA384: TBytes;
    procedure DumpHash(const Name: string);
    procedure SetPreMasterSecret(const Value: TBytes);
    procedure DumpClientFinished;
    procedure SavePlaintext(Plaintext: PTLSPlaintextHeader);
    property CipherSuite: TCipherSuiteTag read FCipherSuite write SetCipherSuite;
  end;

function DebugSession: TDebugTLSSession;
function DebugSend: TDebugTLS;
function DebugRecv: TDebugTLS;

implementation

uses Execute.TLS.Debug.Values;

threadvar
  LDebugSession: TDebugTLSSession;

function Bin2Hex(const Bin: TBytes): string;
begin
  var L := Length(Bin);
  SetLength(Result, 2 * L);
  BinToHex(Bin, PChar(Result), L);
end;

function PByteToStr(P: PByte; L: Integer): string;
begin
  Result := '';
  for var I := 0 to L - 1 do
  begin
    Result := Result + ' ' + P[I].ToString + ',';
  end;
  Result[1] := '(';
  Result[Length(Result)] := ')';
  Result := Result + ' [' + L.ToString + ']';
end;

function BytesToStr(const Bytes: TBytes): string;
begin
  Result := PByteToStr(PByte(Bytes), Length(Bytes));
end;

procedure CloseSession;
begin
  FreeAndNil(LDebugSession);
end;

procedure TDebugTLSSession.ClearHash;
begin
  FHandShakeData.Clear;
//  FSHA1 := TSHA1Hash.Create;
//  FSHA256 := TSHA2Hash.Create(256);
//  FSHA384 := TSHA2Hash.Create(384);
end;

constructor TDebugTLSSession.Create(const AName: string);
begin
  inherited;
  LogProc := DoLog;
  {$IFDEF TLS_LOG_COMMENT}AllocConsole;{$ENDIF}
  AssignFile(FFile, AName);
  Rewrite(FFile);
  WriteLn(FFile, 'var');
  AddExitProc(CloseSession);
//  FSHA1 := TSHA1Hash.Create;
//  FSHA256 := TSHA2Hash.Create(256);
//  FSHA384 := TSHA2Hash.Create(384);
  FHandShakeData := TMemoryStream.Create;
end;

destructor TDebugTLSSession.Destroy;
begin
  FSave.Free;
  FHandShakeData.Free;
  CloseFile(FFile);
  inherited;
end;

procedure TDebugTLSSession.DoLog(const Str: string);
begin
  WriteLn(FFile, Str);
  Flush(FFile);
end;

procedure TDebugTLSSession.DumpConst(const Name: string; Data: Pointer; Size: Integer);
const
  HX: array[0..$F] of Char = '0123456789abcdef';
var
  Ext: string;
  Str: string;
  Ptr: PByte absolute Data;
begin
  if Name = 'Certificate' then
  begin
    Inc(FCertCount);
    Ext := FCertCount.ToString;
  end else begin
    if Name = 'HandshakeData' then
    begin
      Inc(FHandShakes);
      Ext := FHandShakes.ToString;
    end else
    if (Name = 'HandshakeHash') or (Name = 'FinishedDigest') then
    begin
      Ext := FHandShakes.ToString;
    end else begin
      Ext := '';
    end;
  end;

  Log('  Test_' + Name + Ext + ' : TBytes = [ // ' + Size.ToString);

  Str := '   ';
  while Size > 0 do
  begin
    Str := Str + ' $' + HX[Ptr^ shr 4] + HX[Ptr^ and $F];
    Inc(Ptr);
    Dec(Size);
    if Size > 0 then
      Str := Str + ',';
    if Length(Str) > 80 then
    begin
      Log(Str);
      Str := '   ';
    end;
  end;
  if Length(Str) > 3 then
    Log(Str);
  Log('  ];');
end;

function TDebugTLSSession.DigestSHA1: TBytes;
begin
  var H := THashSHA1.Create;
  H.Update(FHandShakeData.Memory^, FHandShakeData.Size);
  Result := H.HashAsBytes;
end;

function TDebugTLSSession.DigestSHA256: TBytes;
begin
  var H := THashSHA2.Create;
  H.Update(FHandShakeData.Memory^, FHandShakeData.Size);
  Result := H.HashAsBytes;
end;

function TDebugTLSSession.DigestSHA384: TBytes;
begin
  var H := THashSHA2.Create(THashSHA2.TSHA2Version.SHA384);
  H.Update(FHandShakeData.Memory^, FHandShakeData.Size);
  Result := H.HashAsBytes;
end;

procedure TDebugTLSSession.DumpHash(const Name: string);
begin
  var D := DigestSHA1;
  DumpConst(Name + '_SHA1', D, Length(D));
  D := DigestSHA256;
  DumpConst(Name + '_SHA256', D, Length(D));
  D := DigestSHA384;
  DumpConst(Name + '_SHA384', D, Length(D));
end;

procedure TDebugTLSSession.SavePlaintext(Plaintext: PTLSPlaintextHeader);
begin
//  if FSave = nil then
//    FSave := TFileStream.Create('TLSStream.dat', fmCreate);
//  FSave.Write(Plaintext^, SizeOf(TTLSPlaintextHeader) + Plaintext.Length);
  WriteLn('>> ', GetContentType(Plaintext.ContentType));
  if Plaintext.ContentType = TContentType.HandShake then
  begin
    var Handshake := PHandshakeHeader(Plaintext.Fragment);
    WriteLn('>>>> ', GetHandshakeType(HandShake.HandShakeType));
  end;
end;

procedure TDebugTLSSession.SetCipherSuite(Value: TCipherSuiteTag);
begin
  FCipherSuite := Value;

   case FCipherSuite of
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    begin
      FHashAlgorithm := TSHA1Hash.Create;
    end;
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
    begin
      FHashAlgorithm := TSHA2Hash.Create(256);
    end;
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
    begin
      FHashAlgorithm := TSHA2Hash.Create(384);
    end;
  else
    FHashAlgorithm := nil;
  end;



end;

procedure TDebugTLSSession.SetPreMasterSecret(const Value: TBytes);
begin
  if FHashAlgorithm = nil then
    Exit;
  FPreMasterSecret := Value;
  SetLength(FMasterSecret, 48);
  FHashAlgorithm.PRF('master secret', FClientRandom, FServerRandom, FPreMasterSecret, FMasterSecret[0], Length(FMasterSecret));
  SetLength(FKeyBlock, 40);
  FHashAlgorithm.PRF('key expansion', FServerRandom, FClientRandom, FMasterSecret, FKeyBlock[0], Length(FKeyBlock));

  var S := TFileStream.Create('PreMasterSecret.dat', fmCreate);
  S.Write(FPreMasterSecret[0], Length(FPreMasterSecret));
  S.Free;
end;

procedure TDebugTLSSession.DumpClientFinished;
begin
  if FHashAlgorithm = nil then
    Exit; // ??
  SetLength(FFinished, 12);

  DebugSend.DumpVar('PreMasterSecret', FPreMasterSecret, Length(FPreMasterSecret));
  DebugSend.DumpVar('MasterSecret', FMasterSecret, Length(FMasterSecret));

  var Digest := FHashAlgorithm.Hash(FHandShakeData.Memory, FHandShakeData.Size);
  DebugSend.DumpVar('Digest_' + FHashAlgorithm.HashSize.ToString, Digest, Length(Digest));
  FHashAlgorithm.PRF('client finished', Digest, FMasterSecret, FFinished[0], Length(FFinished));
  DebugSend.DumpVar('Client_Finished', FFinished, Length(FFinished));
end;

procedure TDebugTLSSession.UpdateDigest(HandShake: PHandShakeHeader);
begin
  if HandShake.HandShakeType = THandShakeType.HelloRequest then
    FHandShakeData.Clear
  else begin
    var Size := SizeOf(THandShakeHeader) + HandShake.Length;
    FHandShakeData.Write(HandShake^, Size);
  end;
end;


var
  ThreadCount: Integer = 0;

function ThreadSuffix: string;
begin
  if GetCurrentThreadId = MainThreadID then
    Result := ''
  else begin
    Inc(ThreadCount);
    Result := '_thread_' + ThreadCount.ToString;
  end;
end;

function DebugSession: TDebugTLSSession;
begin
  if LDebugSession = nil then
  begin
    LDebugSession := TDebugTLSSession.Create('tls_session' + ThreadSuffix + '.txt')
  end;
  Result := LDebugSession;
end;


type
  TFileLoger = class
  private
    FFile: TextFile;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Log(const Str: string);
  end;

constructor TFileLoger.Create;
begin
//  AllocConsole;
  AssignFile(FFile, 'tls_trace' + ThreadSuffix + '.txt');
  Rewrite(FFile);
end;

destructor TFileLoger.Destroy;
begin
  CloseFile(FFile);
end;

procedure TFileLoger.Log(const Str: string);
begin
  AllocConsole;
  WriteLn(Str);
  IOResult;
  WriteLn(FFile, Str);
  Flush(FFile);
end;

threadvar
  LDebugSend: TDebugTLS;
  LDebugRecv: TDebugTLS;
  LFileLoger: TFileLoger;

procedure FreeLoger;
begin
  LDebugSend.Free;
  LDebugRecv.Free;
  LFileLoger.Free;
end;

function FileLoger: TFileLoger;
begin
  if LFileLoger = nil then
  begin
    LFileLoger := TFileLoger.Create;
    AddExitProc(FreeLoger);
  end;
  Result := LFileLoger;
end;

function DebugSend: TDebugTLS;
begin
  if LDebugSend = nil then
  begin
    LDebugSend := TDebugTLS.Create('SEND');
    LDebugSend.LogProc := FileLoger.Log;
  end;
  Result := LDebugSend;
end;

function DebugRecv: TDebugTLS;
begin
  if LDebugRecv = nil then
  begin
    LDebugRecv := TDebugTLS.Create('RECV');
    LDebugRecv.LogProc := FileLoger.Log;
  end;
  Result := LDebugRecv;
end;

const
  HX: array[0..$F] of Char = '0123456789abcdef';

function TTLSPlaintextHolder.GetApplicationData: AnsiString;
begin
  if Header.ContentType <> TContentType.ApplicationData then
  begin
    raise Exception.Create('Expected ApplicationData reply');
  end;
  SetString(Result, PAnsiChar(Data), Size);
  Size := 0;
end;

function TTLSPlaintextHolder.GetHandShake: PHandShakeHeader;
begin
  if Header.ContentType <> TContentType.HandShake then
  begin
    raise Exception.Create('Expected HandShake reply');
  end;
  Result := PHandShakeHeader(Data);
  var Len := SizeOf(THandShakeHeader) + Result.Length;
  if Len > Size then
  begin
    raise Exception.Create('HandShake overflow');
  end;
  Inc(Data, Len);
  Dec(Size, Len);
end;

function TTLSPlaintextHolder.GetAlert: PAlert;
begin
  if Header.ContentType <> TContentType.Alert then
  begin
    raise Exception.Create('Expected Alert reply');
  end;
  Result := PAlert(Data);
  var Len := SizeOf(TAlert);
  if Len < Size then
  begin
    raise Exception.Create('Alert length mismatch');
  end;
  Inc(Data, Len);
  Dec(Size, Len);
end;

function TTLSPlaintextHolder.Load(AData: Pointer; ASize: Integer): Boolean;
begin
  if ASize < SizeOf(TTLSPlaintextHeader) then
    Exit(False);
  Header := AData;
  Size := Header.Length;
  if ASize < SizeOf(TTLSPlaintextHeader) + Size then
    Exit(False);
  Data := Header.Fragment;
  Result := True;
end;

procedure TDebugTLS.BlockRead(var Data; Size: Integer);
begin
  if Size > FSrcLen then
    raise Exception.Create('Out of data');
  Move(FSrcByte^, Data, Size);
  Inc(FSrcByte, Size);
  Dec(FSrcLen, Size);
end;

procedure TDebugTLS.Consume(Stream: TMemoryStream);
begin
  var Size := Debug(Stream.Memory, Stream.Size);
  if Size = 0 then
    Exit;
  DebugSession.FSave.Write(Stream.Memory^, Size);
  var Left := Stream.Size - Size;
  if Left > 0 then
  begin
    var P: PByte := Stream.Memory;
    Inc(P, Size);
    Move(P^, Stream.Memory^, Left);
    Stream.Size := Left;
  end else begin
    Stream.Clear;
  end;
end;

constructor TDebugTLS.Create(const AName: string);
begin
  FName := AName;
end;

function TDebugTLS.GetByte: Byte;
begin
  BlockRead(Result, SizeOf(Result));
end;

function TDebugTLS.GetWord: Word;
begin
  BlockRead(Result, SizeOf(Result));
  Result := Swap(Result);
end;

function TDebugTLS.GetVariableLen: Integer;
var
  Count: Integer;
  Index: Integer;
begin
  Result := GetByte;
  if Result > 128 then
  begin
    Count := Result and $7F;
    Result := 0;
    for Index := 1 to Count do
    begin
      Result := Result shl 8 + GetByte;
    end;
  end;
end;

procedure TDebugTLS.Log(const Msg: string);
var
  Len: Integer;
begin
  Len := Length(FSrcPad);
  if FIter <> Len then
    SetLength(FSrcPad, FIter);
  while Len < Length(FSrcPad) do
  begin
    Inc(Len);
    FSrcPad[Len] := ' ';
  end;
//  if Assigned(FLogProc) then
//    FLogProc('@' + IntToStr(Integer(FSrcByte) - Integer(FSrcStart)) + '/' + IntToStr(FSrcEnd) + '/' + IntToStr(Integer(FSrcByte) - Integer(FSrcStart) + FSrcLen))
//  else
//    WriteLn('@', Integer(FSrcByte) - Integer(FSrcStart));
  if Assigned(FLogProc) then
    FLogProc(FSrcPad + Msg)
  else begin
    AllocConsole;
    WriteLn(FSrcPad, Msg);
  end;
end;

function DumpByte(b: Byte): Char;
begin
  case b of
    32..126: Result := Char(b);
  else
    Result := '.';
  end;
end;

procedure TDebugTLS.Dump(Data: Pointer; Size: Integer);
const
  HX: array[0..$F] of Char = '0123456789abcdef';
var
  Str: string;
  Ptr: PByte absolute Data;
  i,x: Integer;
begin
  SetLength(Str, 3 * 16 + 1 + 16);
  Str[3 * 16 + 1] := '`';
  while Size > 0 do
  begin
    x := 0;

    for i := 0 to 15 do
    begin
      Str[3 * x + 1] := HX[Ptr^ shr 4];
      Str[3 * x + 2] := HX[Ptr^ and $F];
      Str[3 * x + 3] := ' ';
      Str[3 * 16 + 2 + x] := DumpByte(Ptr^);
      Inc(x);
      Inc(Ptr);
      Dec(Size);
      if Size = 0 then
        Break;
    end;

    while x < 16 do
    begin
      Str[3 * x + 1] := '-';
      Str[3 * x + 2] := '-';
      Str[3 * x + 3] := ' ';
      Str[3 * 16 + 2 + x] := ' ';
      Inc(x);
    end;

    Log(Str);
  end;
end;

procedure TDebugTLS.DumpVar(const Title: string; Data: Pointer; Size: Integer);
begin
  if ProtocolDebug then
  begin
    Log(Title + ' { // ' + Size.ToString);
    Inc(FIter);
    Dump(Data, Size);
    Dec(FIter);
    Log('}');
  end;
end;

procedure TDebugTLS.DumpSrc(const Title: string; Size: Integer);
begin
  DumpVar(Title, FSrcByte, Size);
  Inc(FSrcByte, Size);
  Dec(FSrcLen, Size);
end;

function TDebugTLS.BeginIter(const Title: string; Size: Integer = -1): Integer;
begin
  Result := 0;
  Log(Title + ' {');// // ' + Size.ToString + ' out of ' + IntToStr(FSrcLen));
  if Size >= 0 then
  begin
    Result := FSrcLen - Size;
    if Result < 0 then
    begin
      raise Exception.Create('Data underflow');
    end;
    FSrcLen := Size;
  end;
  Inc(FIter);
end;

procedure TDebugTLS.EndIter(Save: Integer = -1);
begin
  if (Save > -2) and (FSrcLen > 0) then
  begin
    BeginIter('ExtraData');
    Dump(FSrcByte, FSrcLen);
    Inc(FSrcByte, FSrcLen);
    FSrcLen := 0;
    EndIter();
  end;
  Dec(FIter);
  Log('}');
  if Save >= 0 then
    FSrcLen := Save;
end;

// DER

procedure TDebugTLS.DebugDERSequence(Tag: Byte; Len: Integer);
var
  Save: Integer;
begin
  Save := BeginIter('SEQUENCE_' + IntToHex(Tag), Len);
  while FSrcLen > 0 do
    DebugDER();
  EndIter(Save);
end;

procedure TDebugTLS.DebugDERInteger(Tag: Byte; Len: Integer);
var
  Save: Integer;
  Value: Integer;
  Index: Integer;
begin
  Save := BeginIter('INTEGER_' + IntToHex(Tag), Len);
  if Len <= 4 then
  begin
    Value := 0;
    for Index := 1 to Len do
      Value := Value shl 8 + GetByte;
    Log(IntToStr(Value) + ' // ' + IntToStr(Len) + ' bytes');
  end else begin
    Dump(FSrcByte, FSrcLen);
    Inc(FSrcByte, Len);
    Dec(FSrcLen, Len);
  end;
  EndIter(Save);
end;

procedure TDebugTLS.DebugDEROID(Tag: Byte; Len: Integer);
var
  OID : string;
begin
  OID := ReadOID(Len);
  Log('OID_' + IntToHex(Tag) + ' : ' + OID);
end;

function TDebugTLS.ReadOID(Len: Integer): string;
var
  Save: Integer;
begin
  Save := FSrcLen - Len;
  FSrcLen := Len;
  var Value := GetByte;
  Result := IntToStr(value div 40) + '.' + IntToStr(Value mod 40);
  while FSrcLen > 0 do
  begin
    Value := 0;
    var Part := GetByte;
    while Part and $80 > 0 do
    begin
      Inc(Value, Part and $7F);
      Value := Value shl 7;
      Part := GetByte;
    end;
    Inc(Value, Part);
    Result := Result + '.' + IntToStr(Value);
  end;
  FSrcLen := Save;
end;

procedure TDebugTLS.TraceHandShakes;
begin
  var HandShake: PHandShakeHeader := DebugSession.FHandShakeData.Memory;
  var Size := DebugSession.FHandShakeData.Size;
  BeginIter('HandShakes');
  Log('Length = ' + Size.ToString);
  var H1 := THashSHA1.Create;
  var H2 := THashSHA2.Create;
  H1.Update(HandShake^, Size);
  H2.Update(HandShake^, Size);
  while Size > 0 do
  begin
    Log(GetHandShakeType(HandShake.HandShakeType) + ' : ' + HandShake.Length.ToString);
    var L := Sizeof(THandShakeHeader) + HandShake.Length;
    Inc(PByte(HandShake), L);
    Dec(Size, L);
  end;
  Log('SHA1 = ' + H1.HashAsString);
  Log('SHA2 = ' + H2.HashAsString);
  EndIter(-2);
end;

procedure TDebugTLS.DebugDERUTF8String(Tag: Byte; Len: Integer);
var
  Str: UTF8String;
begin
  SetLength(Str, Len);
  BlockRead(Str[1], Len);
  Log('UTF8_' + IntToHex(Tag) + ' : ' + string(Str));
end;

procedure TDebugTLS.DebugDigest(Data: TMemoryStream);
begin
  var P: PByte := Data.Memory;
  var S := Data.Size;
  BeginIter('DigestData');
  while S > 0 do
  begin
    var HandShake: PHandShakeHeader := PHandShakeHeader(P);
    DebugHandshake(HandShake);
    var L := SizeOf(THandShakeHeader) + HandShake.Length;
    Inc(P, L);
    Dec(S, L);
  end;
  EndIter();
end;

procedure TDebugTLS.DebugDERAnsiString(Tag: Byte; Len: Integer);
var
  Str: AnsiString;
begin
  SetLength(Str, Len);
  BlockRead(Str[1], Len);
  Log('ANSI_' + IntToHex(Tag) + ' : ' + string(Str));
end;

procedure TDebugTLS.DebugDERTime(Tag: Byte; Len: Integer);
var
  Str: AnsiString;
begin
  SetLength(Str, Len);
  BlockRead(Str[1], Len);
  Log('UTC_' + IntToHex(Tag) + ' : ' + string(Str));
end;

procedure TDebugTLS.DebugDER;
var
  Tag: Byte;
  Len: Integer;
begin
  Tag := GetByte;
  Len := GetVariableLen;
  Assert(Len <= FSrcLen);
  case Tag of
    $02 : DebugDERInteger(Tag, Len);
    $05 : Log('NULL_05 // ' + IntToStr(Len));
    $06 : DebugDEROID(Tag, Len);
    $0C : DebugDERUTF8String(Tag, Len);
    $13 : DebugDERAnsiString(Tag, Len);
    $17 : DebugDERTime(Tag, Len);
    $30,
    $31,
    $A0,
    $A3 : DebugDERSequence(Tag, Len);
  else
    Log('DER_' + IntToHex(Tag) + ' // ' + IntToStr(Len));
    Dump(FSrcByte, Len);
    Inc(FSrcByte, Len);
    Dec(FSrcLen, Len);
  end;
end;

procedure TDebugTLS.DebugCA;
(*
  SEQUENCE_30 {
    SEQUENCE_31 {
      SEQUENCE_30
        OID 2.5.4.x
        STRING Value
      }
    }
    SEQUENCE_31 {
      SEQUENCE_30
        OID 2.5.4.x
        STRING Value
      }
    }
    ...
  }
*)
begin
  var Name := '';
  var Tag := GetByte;
  Assert(Tag = $30); // SEQUENCE
  var Len := GetVariableLen;
  var Save := FSrcLen - Len;
  FSrcLen := Len;
  while FSrcLen > 0 do
  begin
    Name := Name + '/' + ReadCA;
  end;
  Log(Name);
  FSrcLen := Save;
end;

function TDebugTLS.ReadCA: string;
begin
  var Tag := GetByte;
  Assert(Tag = $31); // SEQUENCE
  GetVariableLen;
  Tag := GetByte;
  Assert(Tag = $30);  // SEQUENCE
  GetVariableLen;
  Tag := GetByte;
  Assert(Tag = $06); // OID
  var OID := ReadOID(GetVariableLen);
  Tag := GetByte;
  Assert((Tag = $0C) or (Tag = $13)); // STRING
  var Value: UTF8String;
  SetLength(Value, GetVariableLen);
  BlockRead(Value[1], Length(Value));
  Result := '';
  if OID.StartsWith('2.5.4.') then
  begin
    case StrToInt(Copy(OID, 7)) of
       3: Result := 'CN';
       4: Result := 'SN';
       6: Result := 'C';
      10: Result := 'ORG';
      11: Result := 'OU';
      12: Result := 'T';
      42: Result := 'GN';
    end;
  end;
  if Result = '' then
    Result := '(' + OID + ')';
  if Tag = $0C then
    Result := Result + ':';
  Result := Result + '=' + string(Value);
end;

// TLS

procedure TDebugTLS.DebugRandom(const Random: TRandom);
begin
  Log('Random.Time: ' + DateTimeToStr(System.DateUtils.UnixToDateTime(LSwap(Random.Time))) + ' (' + IntToStr(LSwap(Random.Time)) + ')');
  DumpVar('Random.Data', @Random.Data, Length(Random.Data));
end;

procedure TDebugTLS.DebugSessionID(const ID: TBytes);
begin
  if Length(ID) = 0 then
    Log('SessionID.Length = 0')
  else
    DumpVar('SessionID', ID, Length(ID));
end;

procedure TDebugTLS.DebugSignatureAlgorithms(Extension: PExtensionHeader);
begin
  var SignatureAlgorithms: PSignatureAlgorithmsExtension := Extension.Payload;
  Log('Signatures {');
  Inc(FIter);
  var Count := SignatureAlgorithms.Size;
  if Count and 1 <> 0 then
    raise Exception.Create('SignatureAligorithms Size error');
  if Extension.Length <> 2 + Count then
    raise Exception.Create('SignatureAligorithms Size error');
  Count := Count div 2;
  for var I := 0 to Count - 1 do
    Log(GetSignatureScheme(SignatureAlgorithms.Signatures[I].SignatureScheme));
  Dec(FIter);
  Log('}');
end;

procedure TDebugTLS.DebugSupportedVersions(Extension: PExtensionHeader; Client: Boolean);
begin
  if Client then
  begin
    var SupportedVersions := PClientSupportedVersionsExtension(Extension.Payload);
    Log('SupportedVersions {');
    Inc(FIter);
    var Count := SupportedVersions.Bytes;
    if Count and 1 <> 0 then
      raise Exception.Create('SupportedVersions Size error');
    if Extension.Length <> 1 + Count then
      raise Exception.Create('SupportedVersions Size error');
    Count := Count div 2;
    for var I := 0 to Count - 1 do
      Log(GetProtocolVersion(TProtocolVersion(SupportedVersions.Versions[I])));
  end else begin
    Log('SupportedVersion {');
    if Extension.Length <> 2 then
      raise Exception.Create('SupportedVersion Size error');
    Log(GetProtocolVersion(PProtocolVersion(Extension.Payload)^));
    Inc(FIter);
  end;
  Dec(FIter);
  Log('}');
end;

procedure TDebugTLS.DebugCipherSuites(const Suites: PCipherList);
begin
  BeginIter('CipherSuites');
  for var I := 0 to Suites.Count - 1 do
  begin
    Log(GetCipherSuite(Suites.Items[I]));
  end;
  EndIter();
end;

procedure TDebugTLS.DebugCompressionMethods(const Compressions: PCompressionList);
begin
  BeginIter('CompressionMethods');
  for var I := 0 to Compressions.Count - 1 do
  begin
    Log(GetCompressionMethod(Compressions.Items[I]));
  end;
  EndIter();
end;

procedure TDebugTLS.DebugServerName(Extension: PExtensionHeader);
begin
  var ServerName: PServerNameExtension := Extension.Payload;
  var Size := Extension.Length;
  if Size = 0 then
    Exit;
  if (ServerName.NameType <> HostName)
  or (ServerName.Size + 2 <> Size)
  or (Size <> SizeOf(TServerNameExtension)  - 1 { FName} + ServerName.NameLength) then
    raise Exception.Create('Servername extension error');
  Log('HostName : ' + string(ServerName.Name));
end;

procedure TDebugTLS.DebugSupportedGroups(Extension: PExtensionHeader);
begin
  var Groups: PSupportedGroupsExtension := Extension.Payload;
  Log('Groups {');
  Inc(FIter);
  var Count := Groups.Size;
  if Count and 1 <> 0 then
    raise Exception.Create('SupportedGroup error');
  if Extension.Length <> 2 + Count then
    raise Exception.Create('SupportedGroup size error');
  Count := Count div 2;
  for var I := 0 to Count - 1 do
    Log(GetSupportedGroup(Groups.Groups[I]));
  Dec(FIter);
  Log('}');
end;

procedure TDebugTLS.DebugType(Data: Pointer; Len: Integer;
  ContentType: TContentType);
begin
  BeginIter(FName);
  var TLSRecord: TTLSPlaintextHolder;
  TLSRecord.Size := Len;
  TLSRecord.Data := Data;
  var Header : TTLSPlaintextHeader;
  Header.ContentType := ContentType;
  Header.ProtocolVersion.major := 3;
  Header.ProtocolVersion.minor := 3;
  Header.Length := Len;
  TLSRecord.Header := @Header;
  var CCS := FChangeCipherSpec;
  FChangeCipherSpec := False;
  DebugTLSRecord(TLSRecord);
  FChangeCipherSpec := CCS;
  EndIter;
end;

procedure TDebugTLS.DebugECPointFormats(Extension: PExtensionHeader);
var
  F: ^TECPointFormat;
begin
  var Formats: PECPointFormatsExtension := Extension.Payload;
  if Extension.Length <> 1 + Formats.Count then
    raise Exception.Create('ECPointFormats size error');
  F := @Formats.Formats[0];
  var Str: string;
  for var I := 1 to Formats.Count do
  begin
    Str := Str + ',' + GetECPointFormat(F^);
    Inc(F);
  end;
  if Str <> '' then
    Str[1] := ' ';
  Log('ECPointFormats : ' + Str);
end;

procedure TDebugTLS.DebugExtension(Extension: PExtensionHeader; Client: Boolean);
begin
  BeginIter('Extension');
  Log('ExtensionType: ' + GetExtensionType(Extension.ExtensionType));
  Log('Length: ' + IntToStr(Extension.Length));
  case Extension.ExtensionType of
    ServerName: DebugServerName(Extension);
    SupportedGroups: DebugSupportedGroups(Extension);
    ECPointFormats : DebugECPointFormats(Extension);
    SignatureAlgorithms: DebugSignatureAlgorithms(Extension);
    SupportedVersions: DebugSupportedVersions(Extension, Client);
    PSKeyExchangeModes: DebugPSKeyExchangeModes(Extension);
    KeyShare: DebugKeyShare(Extension, Client);
//    ExtendedMasterSecret: ;
//    SessionTicketTLS: ;
    RenegotiationInfo:
    begin
//      Log('Value : ' + IntToStr(PByte(Extension.Payload)^));
      DumpVar('Value', Extension.Payload, Extension.Length);
    end;
  end;
  EndIter();
end;

function TDebugTLS.DebugExtensions(ExtensionList: PExtensionList; Client: Boolean): Word;
begin
  if ProtocolDebug then
    BeginIter('Extensions');
  var Size := ExtensionList.Size;
  var Index := 0;
  while Index < Size do
  begin
    var Ext: PExtensionHeader := @ExtensionList.Data[Index];
    Inc(Index, SizeOf(TExtensionHeader));
    if Index > Size then
      raise Exception.Create('Extension overflow');
    Inc(Index, Ext.Length);
    if Index > Size then
      raise Exception.Create('Extension overflow');
    if ProtocolDebug then
      DebugExtension(Ext, Client);
  end;
  if ProtocolDebug then
    EndIter();
  Result := 2 + size;
end;

procedure TDebugTLS.DebugClientHello(HandShake: PHandShakeHeader);
begin
  FChangeCipherSpec := False;
  FPublicKey.modulus := nil;

  BeginIter('ClientHello');
  var Hello : PClientHello := HandShake.Payload;

  if HandShake.Length < SizeOf(TClientHello) then
    raise Exception.Create('ClientHello overflow');

  if HandShake.Length < SizeOf(TClientHello)
                      + Hello.SessionIDLen
                      + 2 + Hello.CipherList.Size
                      + 1 + Hello.CompressionList.Count
  then
    raise Exception.Create('ClientHello overflow');


  Log('ProtocolVersion: ' + GetProtocolVersion(Hello.ProtocolVersion));
  if ProtocolDebug then
  begin
    DebugRandom(Hello.Random);
    DebugSessionID(Hello.SessionID);
    DebugCipherSuites(Hello.CipherList);
    DebugCompressionMethods(Hello.CompressionList);
  end;
  var Size := SizeOf(TClientHello)
            + Hello.SessionIDLen
            + 2 + Hello.CipherList.Size
            + 1 + Hello.CompressionList.Count;
  if Hello.HasExtensions(HandShake.Length) then
  begin
    Inc(Size, DebugExtensions(Hello.ExtensionList, True));
  end;
  if HandShake.Length <> Size then
    raise Exception.Create('ClientHello overflow ' + HandShake.Length.ToString + '/' + Size.ToString + ' (' + (HandShake.Length - Size).ToString + ')');

  DebugSession.FClientRandom := Hello.Random;
  EndIter();
end;

procedure TDebugTLS.DebugServerHello(HandShake: PHandShakeHeader);
begin
  BeginIter('ServerHello');
  var Hello: PServerHello := HandShake.Payload;
  Log('ProtocolVersion: ' + GetProtocolVersion(Hello.ProtocolVersion));
  if ProtocolDebug then
  begin
    DebugRandom(Hello.Random);
    DebugSessionID(Hello.SessionID);
    Log('CipherSuite: ' + GetCipherSuite(Hello.Cipher));
    Log('CompressionMethod: ' + GetCompressionMethod(Hello.Compression));
    if Hello.HasExtensions(HandShake.Length) then
      DebugExtensions(Hello.ExtensionList, False);
  end;

  DebugSession.CipherSuite := Hello.Cipher;
  DebugSession.FServerRandom := Hello.Random;

  EndIter();
end;

procedure TDebugTLS.DebugCertificate;
begin
  var Context := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, FSrcByte, FSrcLen);
  if Context = nil then
    Exit;
  if FPublicKey.modulus = nil then
  begin
    FPublicKey.LoadKey(Context.pCertInfo.SubjectPublicKeyInfo.PublicKey.pbData, Context.pCertInfo.SubjectPublicKeyInfo.PublicKey.cbData);
  end;
  var Save := BeginIter('Certificate', Context.cbCertEncoded);
  var Name := CertName(Context, Context.pCertInfo.Subject);
  Log('// ' + Name);
  var CN := Pos('CN=', Name);
  if CN > 0 then
  begin
    var SP := Pos(',', Name, CN);
    if SP > 0 then
    begin
      Name := Copy(Name, CN + 3, SP - CN - 3);
      Name := StringReplace(Name, '*', '_', [rfReplaceAll]);
      var P := TPointerStream.Create(FSrcByte, FSrcLen, True);
      P.SaveToFile(Name + '.crt');
      P.Free;
    end;
  end;

//  DumpSrc('Dump', Context.cbCertEncoded);
  Inc(FSrcByte, Context.cbCertEncoded);
  Dec(FSrcLen, Context.cbCertEncoded);

  CertFreeCertificateContext(Context);
  EndIter(Save);
end;

procedure TDebugTLS.DebugCertificateRequest(HandShake: PHandShakeHeader);
begin
  FSrcLen := HandShake.Length;
  FSrcByte := HandShake.Payload;
  BeginIter('CertificateRequest');
  var Count: Integer := GetByte;
  BeginIter('ClientCertificateType');
  for var I := 0 to Count - 1 do
    Log(GetClientCertificateType(TClientCertificateType(GetByte)));
  EndIter(-2);
  Count := GetWord;
  BeginIter('SignatureAndHashAlgorithm');
  while Count > 0 do
  begin
    var Alg: TSignatureAndHashAlgorithm;
    BlockRead(Alg, SizeOf(Alg));
    Dec(Count, 2);
    Log(GetSignatureAndHashAlgorithm(Alg));
  end;
  EndIter(-2);
  Count := GetWord;
  BeginIter('DistinguishedName');
  while Count > 0 do
  begin
    var Len := GetWord;
    Dec(Count, 2 + Len);
    DebugCA;
  end;
  EndIter(-2);
  EndIter();
end;

procedure TDebugTLS.DebugCertificates(HandShake: PHandShakeHeader);
var
  TotalLen, CertLen: TUnsignedInteger24;
begin
  FSrcLen := HandShake.Length;
  FSrcByte := HandShake.Payload;

  BlockRead(TotalLen, SizeOf(TotalLen));
  BeginIter('Certificates', TotalLen.Value);
  while FSrcLen > 0 do
  begin
    BlockRead(CertLen, SizeOf(CertLen));
    if ProtocolDebug then
      Log('CertLength = ' + CertLen.Value.ToString);
    DebugCertificate;
  end;
  EndIter();
end;

procedure TDebugTLS.DebugCertificateVerify(HandShake: PHandShakeHeader);
begin
  DebugSession.DumpHash('CertificateVerify');
  FSrcLen := HandShake.Length;
  FSrcByte := HandShake.Payload;
  BeginIter('CertificateVerify');
  var Alg: TSignatureAndHashAlgorithm;
  BlockRead(Alg, SizeOf(Alg));
  Log(GetSignatureAndHashAlgorithm(Alg));
  var Len := GetWord;
  if AdvancedDebug and (FPublicKey.modulus <> nil) and (Len = 256) then
  begin
    TraceHandShakes;
    var D: TBytes;
    var N: string;
    case Alg.Hash of
      ThashAlgorithm.sha1:
      begin
        D := DebugSession.DigestSHA1;
        N := 'Digest_SHA1';
      end;
      ThashAlgorithm.sha256:
      begin
        D := DebugSession.DigestSHA256;
        N := 'Digest_SHA256';
      end;
      ThashAlgorithm.sha384:
      begin
        D := DebugSession.DigestSHA384;
        N := 'Digest_SHA384';
      end;
    end;
    DumpVar(N, D, Length(D));
    var Decoded := FPublicKey.DeCrypt(FSrcByte, Len);
    if (Length(Decoded) = Length(SHA1_OID) + 20) and CompareMem(Decoded, SHA1_OID, Length(SHA1_OID)) then
      DumpVar('Decoded_SHA1', @Decoded[Length(SHA1_OID)], 20)
    else
    if (Length(Decoded) = Length(SHA256_OID) + 32) and CompareMem(Decoded, SHA256_OID, Length(SHA256_OID)) then
      DumpVar('Decoded_SHA256', @Decoded[Length(SHA256_OID)], 32)
    else
    if (Length(Decoded) = Length(SHA384_OID) + 48) and CompareMem(Decoded, SHA384_OID, Length(SHA384_OID)) then
      DumpVar('Decoded_SHA384', @Decoded[Length(SHA384_OID)], 48)
    else
      DumpVar('Decoded', Decoded, Length(Decoded));

  end;
  DebugSession.DumpConst('CertificateVerify', FSrcByte, Len);
  DumpSrc('Signature', Len);
  EndIter();
end;

procedure TDebugTLS.DebugPSKeyExchangeModes(Extension: PExtensionHeader);
begin
  var PSKeyExchangeModes := PPSKeyExchangeModes(Extension.Payload);
  Log('PSKeyExchangeModes {');
  Inc(FIter);
  var Count := PSKeyExchangeModes.Count;
  if Extension.Length <> 1 + Count then
    raise Exception.Create('PSKeyExchangeModes Size error');
//  for var I := 0 to Count - 1 do
//    Log(GetPSKeyExchangeMode(PSKeyExchangeModes.Modes[I]));
  Dec(FIter);
  Log('}');
end;

procedure TDebugTLS.DebugPubKey;
var
  Len: Integer;
begin
  DebugSession.DumpConst('ClientKeyExchange', FSrcByte, FSrcLen);
  // ECDHE_RSA
  if FSrcLen = 1 + FSrcByte^ then
    Len := GetByte
  else
  // RSA
  if FSrcLen = 2 + Swap(PWord(FSrcByte)^) then
    Len := GetWord
  else
  // Other ?
    Len := 0;

  if Len > 0 then
    DumpSrc('PubKey', Len);
end;

procedure TDebugTLS.DebugServerKeyExchange(HandShake: PHandShakeHeader);
begin
  FSrcLen := HandShake.Length;
  FSrcByte := HandShake.Payload;
  Log('CurveType : ' + GetCurveType(TCurveType(GetByte)));
  Log('NamedCurve : ' + GetSupportedGroup(TSupportedGroup(GetWord)));
  var KeyLen := GetByte;
  if ProtocolDebug then
    DumpSrc('Key', KeyLen);
  var Hash := THashAlgorithm(GetByte);
  if ProtocolDebug then
  begin
    Log('HashAlgorithm : ' + GetHashAlgorithm(Hash));
    Log('SignatureAlgorithm : ' + GetSignatureAlgorithm(TSignatureAlgorithm(GetByte)));
  end;
  var SignLen := GetWord;
  if AdvancedDebug and (FPublicKey.modulus <> nil) then
  begin
    var D: TBytes;
    var N: string;
    case Hash of
      ThashAlgorithm.sha1:
      begin
        var H := THashSHA1.Create;
        H.Update(DebugSession.FClientRandom, SizeOf(TRandom));
        H.Update(DebugSession.FServerRandom, SizeOf(TRandom));
        H.Update(HandShake.Payload^, SizeOf(TServerKeyExchange) + KeyLen);
        N := 'Digest_SHA1';
        D := H.HashAsBytes;
      end;
      THashAlgorithm.sha256:
      begin
        var H := THashSHA2.Create;
        H.Update(DebugSession.FClientRandom, SizeOf(TRandom));
        H.Update(DebugSession.FServerRandom, SizeOf(TRandom));
        H.Update(HandShake.Payload^, SizeOf(TServerKeyExchange) + KeyLen);
        N := 'Digest_SHA256';
        D := H.HashAsBytes;
      end;
      THashAlgorithm.sha384:
      begin
        var H := THashSHA2.Create(THashSHA2.TSHA2Version.sha384);
        H.Update(DebugSession.FClientRandom, SizeOf(TRandom));
        H.Update(DebugSession.FServerRandom, SizeOf(TRandom));
        H.Update(HandShake.Payload^, SizeOf(TServerKeyExchange) + KeyLen);
        N := 'Digest_SHA384';
        D := H.HashAsBytes;
      end;
    end;
    DumpVar(N, D, Length(D));
    var Decoded := FPublicKey.DeCrypt(FSrcByte, SignLen);
    if (Length(Decoded) = Length(SHA1_OID) + 20) and CompareMem(Decoded, SHA1_OID, Length(SHA1_OID)) then
      DumpVar('Decoded_SHA1', @Decoded[Length(SHA1_OID)], 20)
    else
    if (Length(Decoded) = Length(SHA256_OID) + 32) and CompareMem(Decoded, SHA256_OID, Length(SHA256_OID)) then
      DumpVar('Decoded_SHA256', @Decoded[Length(SHA256_OID)], 32)
    else
    if (Length(Decoded) = Length(SHA384_OID) + 48) and CompareMem(Decoded, SHA384_OID, Length(SHA384_OID)) then
      DumpVar('Decoded_SHA384', @Decoded[Length(SHA384_OID)], 48)
    else
      DumpVar('Decoded', Decoded, Length(Decoded));
  end;
  DumpSrc('Signature', SignLen)
end;

procedure TDebugTLS.DebugClientKeyExchange(HandShake: PHandShakeHeader);
begin
  if ProtocolDebug then
  begin
    FSrcLen := HandShake.Length;
    FSrcByte := HandShake.Payload;
    DebugPubKey;
  end;
end;

procedure TDebugTLS.DebugChangeCipherSpec(var TLSRecord: TTLSPlaintextHolder);
begin
  BeginIter('ChangeCipherSpec');
  Log('Message : ' + IntToStr(TLSRecord.Data^));
  EndIter();
  FChangeCipherSpec := True;
end;

procedure TDebugTLS.DebugHandShakes(var TLSRecord: TTLSPlaintextHolder);
begin
  while TLSRecord.Size > 0 do
  begin
    DebugHandshake(TLSRecord.GetHandShake);
  end;
end;

procedure TDebugTLS.DebugHelloRequest(HandShake: PHandShakeHeader);
begin
  Assert(HandShake.Length = 0);
end;

procedure TDebugTLS.DebugKeyShare(Extension: PExtensionHeader; Client: Boolean);
begin
  Log('KeyShare {');
  Inc(FIter);
  var KeyShare: PKeyShareExtension;
  if Client then
  begin
    KeyShare := @PClientKeyShareExtension(Extension.Payload).KeyShare
  end else begin
    KeyShare := PKeyShareExtension(Extension.Payload);
  end;
  var Key := KeyShare.GetKey;
  Log('CurveName: ' + GetSupportedGroup(KeyShare.Curve));
  DumpVar('PublicKey', Key, Length(Key));
  Dec(FIter);
  Log('}');
  if Client then
  begin
    if Extension.Length <> 2 + 2 + 2 + Length(Key) then
      raise Exception.Create('KeyShareExtension Size error');
    if Extension.Length <> PClientKeyShareExtension(Extension.Payload).Size + 2 then
      raise Exception.Create('KeyShareExtension Size error');
  end else begin
    if Extension.Length <> 2 + 2 + Length(Key) then
      raise Exception.Create('KeyShareExtension Size error');
  end;
end;

procedure TDebugTLS.DebugNewSessionTicket(HandShake: PHandShakeHeader);
begin
//  BeginIter('NewSessionTicket');
//  var NewSessionTicket: PNewSessionTicket := HandShake.Payload;
//  Log('TicketLifetime: ' + IntToStr(NewSessionTicket.TicketLifetime));
//  Log('TicketAgeAdd: ' + IntToStr(NewSessionTicket.TicketAgeAdd));
//  var B := NewSessionTicket.Nonce;
//  DumpVar('Nonce',  B, Length(B));
//  B := NewSessionTicket.Ticket;
//  DumpVar('Ticket', B, Length(B));
//  B := NewSessionTicket.Extension;
//  DumpVar('Extension', B, Length(B));
//  EndIter();
//  if HandShake.Length <> SizeOf(TNewSessionTicket) + NewSessionTicket.NonceLength + SizeOf(Word) + NewSessionTicket.TicketLength + SizeOf(Word) + NewSessionTicket.ExtensionLength then
//    raise Exception.Create('NewSessionTicket Size error');
end;

procedure TDebugTLS.DebugHandShake(HandShake: PHandshakeHeader);
begin
  BeginIter('HandShake');
  Log('HandShakeType: ' + GetHandshakeType(HandShake.HandShakeType));
  Log('Length: ' + IntToStr(HandShake.Length));
  case HandShake.HandShakeType of
    HelloRequest: DebugHelloRequest(HandShake);
    ClientHello: DebugClientHello(HandShake);
    ServerHello: DebugServerHello(HandShake);
    NewSessionTicket: DebugNewSessionTicket(HandShake);
    Certificate: DebugCertificates(HandShake);
    ServerKeyExchange: DebugServerKeyExchange(HandShake);
    ClientKeyExchange: DebugClientKeyExchange(HandShake);
    CertificateRequest: DebugCertificateRequest(HandShake);
    CertificateVerify: DebugCertificateVerify(HandShake);
    ServerHelloDone: Assert(HandShake.Length = 0);//Log('ServerHelloDone');
    Finished: DebugFinished(HandShake);
  else
    raise Exception.Create('Unknown HandShakeType');
  end;
  DebugSession.UpdateDigest(HandShake);
  EndIter();
end;

function TDebugTLS.Debug(Data: Pointer; Len: Integer; Uncrypted: Boolean = False): Integer;
var
  TLSRecord: TTLSPlaintextHolder;
begin
  Result := 0;
  while TLSRecord.Load(Data, Len) do
  begin
    if Result = 0 then
      BeginIter(FName);
    var Size := SizeOf(TTLSPlaintextHeader) + TLSRecord.Size;
    DebugTLSRecord(TLSRecord, Uncrypted);
    Inc(PByte(Data), Size);
    Dec(Len, Size);
    Result := Result + Size;
  end;
  if Result > 0 then
    EndIter();
end;

procedure TDebugTLS.DebugFinished(HandShake: PHandShakeHeader);
begin
  if HandShake.Length <> 12 then
    raise Exception.Create('Finished overflow');
  BeginIter('Finished');
  if ProtocolDebug then
  begin
    Dump(HandShake.Payload, SizeOf(TFinished));
    if AdvancedDebug and (FName = 'SEND') then
      DebugSession.DumpClientFinished;
  end;
  EndIter;
end;

procedure TDebugTLS.DebugTLSRecord(var TLSRecord: TTLSPlaintextHolder; Uncrypted: Boolean = False);
begin
  //DebugSession.SavePlaintext(TLSRecord.Header);
  BeginIter('TLSPlaintext');
  Log('ContentType: ' + GetContentType(TLSRecord.Header.ContentType));
  Log('ProtocolVersion: ' + GetProtocolVersion(TLSRecord.Header.ProtocolVersion));
  Log('Length: ' + IntToStr(TLSRecord.Size));
  if FChangeCipherSpec and (Uncrypted = False) and TLSRecord.Header.IsCrypted then
  begin
    Log('//Crypted ' + TLSRecord.Size.ToString);
    Dump(TLSRecord.Data, TLSRecord.Size);
  end else
  begin
    case TLSRecord.Header.ContentType of
      HandShake: DebugHandShakes(TLSRecord);
      ChangeCipherSpec: DebugChangeCipherSpec(TLSRecord);
      Alert: DebugAlert(TLSRecord);
      ApplicationData: DebugApplicationData(TLSRecord);
    else
      raise Exception.Create('Unknow ContentType');
    end;
  end;
  EndIter();
end;

procedure TDebugTLS.DebugAlert(var TLSRecord: TTLSPlaintextHolder);
begin
  while TLSRecord.Size > 0 do
  begin
    var Alert := TLSRecord.GetAlert;
    BeginIter('Alert');
    Log('level: ' + GetAlertLevel(Alert.level));
    Log('description: ' + GetAlertDescription(Alert.description));
    EndIter();
  end;
end;

procedure TDebugTLS.DebugApplicationData(var TLSRecord: TTLSPlaintextHolder);
begin
  while TLSRecord.Size > 0 do
  begin
    var Data := TLSRecord.GetApplicationData;
    BeginIter('ApplicationData');
    if Assigned(FLogProc) then
    begin
      FLogProc('<<<');
      FLogProc(string(Data));
      FLogProc('>>>');
    end;
    EndIter();
  end;
end;

end.

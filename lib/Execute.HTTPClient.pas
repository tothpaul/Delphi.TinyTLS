unit Execute.HTTPClient;
{
  HTTP Client (c)2025 Execute SARL
}

interface

{$IFDEF DEBUG}
{.$DEFINE LOG_HTTP}
{.$DEFINE KEEP_HTTP}
{.$DEFINE DEBUG_COOKIE}
{.$DEFINE TRACE_WS}
{$ENDIF}

uses
{$IFDEF DEBUG}Winapi.Windows,{$ENDIF}
  System.SysUtils,
  System.Classes,
  System.ZLib,
  Execute.Sockets,
  Execute.TinyTLS;

type
  TURL = record
    Protocol: UTF8String;
    HostName: UTF8String;
    Port    : UTF8String;
    URI     : UTF8String;
    Target  : UTF8String;
    procedure Decode(const URL: UTF8String);
    class function Encode(const param: UTF8String): UTF8String; static;
  end;

  TCookie = record
    Host  : UTF8String;
    Name  : UTF8String;
    Value : UTF8String;
    Path  : UTF8String;
    Domain: UTF8String;
    function Assign(const Cookie: TCookie): Boolean;
  end;
  TCookies = TArray<TCookie>;

  THeaderField = record
    Name : string;
    Value: string;
  end;

  THeaderFields = record
    Fields: TArray<THeaderField>;
    procedure Add(const NAme, Value: string);
    function HeaderIndex(const Name: string): Integer;
    procedure SetHeader(Index: Integer; const Value: string);
    function GetHeader(const Name: string): string;
    function HasHeader(const Name, Value: string): Boolean;
  end;

  THTTPClient = class
  private
    FHost: UTF8String;
    FPort: Integer;
    FTLS : Boolean;
    FSocket: TSocket;
    FKeepAlive: Boolean;
    FContentType: UTF8String;
    FAccept: UTF8String;
    FAcceptGZIP: Boolean;
    FUserAgent: UTF8String;
    FAuthorization: UTF8String;
    FCustomHeaders: TStringList;
    FCookies: TCookies;
    FHeader: TStringStream;
    FHeaders: THeaderFields;
    FTimeout: Cardinal;
    FLastTick: Cardinal;
    FResponse: UTF8String;
    FResponseCode: Integer;
    function AcceptEncoding: UTF8String;
    function GetCustomHeaders: UTF8String;
    procedure SetCookies(Lst: TStrings);
    function TimedOut: Boolean;
    procedure SendRequest(Req: TStream);
    procedure DoRequest(Req, Rsp: TStream; Body: TStream = nil);
    procedure Request(const Method, URL: UTF8String; Rsp: TStream; Body: TStream = nil);
    function UTF8Request(const Method, URL: UTF8String; Body: TStream): UTF8String;
    procedure SetTLS(Value: Boolean);
    function CookieIndex(const Name, Host: string): Integer;
    procedure ParseCookie(const Value: string);
    procedure AddHeader(P: PAnsiChar; Start: Integer; var Index: Integer);
    procedure ParseHeader;
    procedure ReadChunks(Stream: TStream);
    procedure GetTimeout;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Close;
    function Get(const URL: UTF8String): UTF8String;
    function Post(const URL, Content: UTF8String): UTF8String;
    function Put(const URL, Content: UTF8String): UTF8String;
    procedure Delete(const URL: UTF8String);
    property KeepAlive: Boolean read FKeepAlive write FKeepAlive;
    property ContentType: UTF8String read FContentType write FContentType;
    property Accept: UTF8String read FAccept write FAccept;
    property AcceptGZIP: Boolean read FAcceptGZIP write FAcceptGZIP;
    property UserAgent: UTF8String read FUserAgent write FUserAgent;
    property Authorization: UTF8String read FAuthorization write FAuthorization;
    property CustomHeaders: TStringList read FCustomHeaders;
    property Response: UTF8String read FResponse;
    property ResponseCode: Integer read FResponseCode;
  end;

function wget(const URL: string): string;

implementation

const
  CONNECTION: array[False..True] of AnsiString = ('close', 'keep-alive');

function wget(const URL: string): string;
begin
  var HTTP := THTTPClient.Create;
  try
    Result := string(HTTP.Get(UTF8String(URL)));
  finally
    HTTP.Free;
  end;
end;

type
  TMemoryStreamHelper = class helper for TMemoryStream
    procedure Assign(Source: TMemoryStream);
  end;

procedure TMemoryStreamHelper.Assign(Source: TMemoryStream);
begin
  Clear;
  if Source <> nil then
  begin
    SetPointer(Source.Memory, Source.Size);
    Source.SetPointer(nil, 0);
  end;
end;

function StreamToString(Stream: TStream; Encoding: TEncoding): string;
var
  Data: TBytes;
begin
  Stream.Position := 0;
  SetLength(Data, Stream.Size);
  Stream.Read(PByte(Data)^, Length(Data));
  try
    Result := Encoding.GetString(Data);
  except
    Result := TEncoding.ANSI.GetString(Data);
  end;
end;

function UTF8Pos(const SubStr, Str: UTF8String; Start: Integer = 1): Integer;
var
  L1: Integer;
  L2: Integer;
  B1: PAnsiChar;
  B2: PAnsiChar;
  I: Integer;
  J: Integer;
begin
  L2 := Length(SubStr);
  if L2 = 0 then
    Exit(0);
  L1 := Length(Str) - L2 + 1;
  if Start > 1 then
    Dec(L1, Start - 1)
  else
    Start := 1;
  if L1 <= 0 then
    Exit(0);
  B1 := @Str[Start];
  B2 := Pointer(SubStr);
  for I := 1 to L1 do
  begin
    J := 0;
    while B1[J] = B2[J] do
    begin
      Inc(J);
      if J = L2 then
        Exit(I + Start - 1);
    end;
    Inc(B1);
  end;
  Result := 0;
end;

function UTF8EndsWith(const Str, Sub: UTF8String): Boolean;
begin
  var L1 := High(Str);
  var L2 := High(Sub);
  Result := False;
  if L2 > L1 then
    Exit;
  for var I := 0 to L2 - 1 do
  begin
    if Str[L1 - I] <> Sub[L2 - I] then
      Exit;
  end;
  Result := True;
end;

function UTF8LowerCase(const Str: UTF8String): UTF8String;
begin
  Result := Str;
  for var I := 1 to High(Result) do
  begin
    case Result[I] of
      'A'..'Z': Inc(Result[I], Ord('a') - Ord('A'));
    end;
  end;
end;

function CamelCase(const Str: string): string;
var
  Index: Integer;
  Up   : Boolean;
  Ch   : Char;
begin
  Result := Str;
  Up := True;
  for Index := 1 to Length(Str) do
  begin
    Ch := Str[Index];
    case Ch of
      'a'..'z':
        if Up then
        begin
          Dec(Ch, Ord('a') - Ord('A'));
          Up := False;
        end;
      'A'..'Z':
        if Up then
          Up := False
        else
          Inc(Ch, Ord('a') - Ord('A'));
    else
      Up := True;
    end;
    if Ch <> Str[Index] then
      Result[Index] := Ch;
  end;
end;

procedure DecodeGZip(Stream: TStream);
var
  Decode : TZDecompressionStream;
  Extract: TMemoryStream;
begin
  Stream.Position := 0;
  Decode :=  TZDecompressionStream.Create(Stream, 15 + 16);
  Extract := TMemoryStream.Create;
  Extract.CopyFrom(Decode, 0);
  Decode.Free;
  if Stream.ClassType = TMemoryStream then
    TMemoryStream(Stream).Assign(Extract)
  else
  if Stream is TMemoryStream then
    TMemoryStream(Stream).LoadFromStream(Extract)
  else begin
    Stream.Position := 0;
    Stream.CopyFrom(Extract, 0);
  end;
  Extract.Free;
end;

function GetCSV(const Source: string; var Index: Integer; var Value: string; const Sep: string = ';'): Boolean;
var
  I: Integer;
begin
  I := System.Pos(Sep, Source, Index);
  if I = 0 then
  begin
    Value := Copy(Source, Index);
    Index := Length(Source) + 1;
  end else begin
    Value := Copy(Source, Index, I - Index);
    Index := I + 1;
  end;
  Value := Trim(Value);
  Result := Value <> '';
end;

function GetPair(const Source: string; var Name, Value: string): Boolean;
var
  I: Integer;
begin
  I := System.Pos('=', Source);
  if I = 0 then
    Exit(False);
  Name := Trim(Copy(Source, 1, I - 1));
  Value := Trim(Copy(Source, I + 1));
  Result := True;
end;

{ TURL }

procedure TURL.Decode(const URL: UTF8String);
var
  I1: Integer;
  I2: Integer;
begin
  I1 := UTF8Pos('://', URL);
  if I1 = 0 then
  begin
    Protocol := 'https';
    I1 := 1;
  end else begin
    Protocol := UTF8LowerCase(Copy(URL, 1, I1 - 1));
    Inc(I1, 3);
  end;
  I2 := UTF8Pos('/', URL, I1);
  if I2 = 0 then
  begin
    HostName := Copy(URL, I1);
    URI := '/';
    Target := '';
  end else begin
    HostName := Copy(URL, I1, I2 - I1);
    I1 := UTF8Pos('#', URL, I2);
    if I1 = 0 then
    begin
      URI := Copy(URL, I2);
      Target := '';
    end else begin
      URI := Copy(URL, I2, I1 - I2);
      Target := Copy(URL, I1);
    end;
  end;
  I1 := UTF8Pos(':', HostName);
  if I1 = 0 then
  begin
    if Protocol = 'https' then
      Port := '443'
    else
      Port := '80';
  end else begin
    Port := Copy(HostName, I1 + 1);
    SetLength(HostName, I1 - 1);
  end;
end;

class function TURL.Encode(const param: UTF8String): UTF8String;
const
  HX: array[0..$F] of AnsiChar = '0123456789ABCDEF';
begin
  Result := param;
  var L := Length(Result);
  for var I := 1 to L do
  begin
    case Result[I] of
      '0'..'9', 'a'..'z', 'A'..'Z', '_', '-', '.', '~': { ok } ;
      ' ': Result[I] := '+';
    else
      Result[I] := '%';
      Inc(L, 2); // HH
    end;
  end;
  if L = Length(Result) then
    Exit;
  SetLength(Result, L);
  for var I := Length(param) downto 1 do
  begin
    if Result[I] = '%' then
    begin
      var c := Ord(param[I]);
      Result[L] := HX[c and $F];
      Dec(L);
      Result[L] := HX[c shr 4];
      Dec(L);
    end;
    if L = I then
      Break;
    Result[L] := Result[I];
    Dec(L);
  end;
end;

{ TCookie }

function TCookie.Assign(const Cookie: TCookie): Boolean;
begin
  Result := (Cookie.Host = Host) and (Cookie.Name = Name);
  if Result then
  begin
    Value := Cookie.Value;
    Path := Cookie.Path;
    Domain := Cookie.Domain;
  end;
end;

{ THeaderFields }

procedure THeaderFields.Add(const NAme: string; const Value: string);
begin
  SetHeader(HeaderIndex(Name), Value);
end;

function THeaderFields.HeaderIndex(const Name: string): Integer;
begin
  Result := Length(Fields) - 1;
  while Result >= 0 do
  begin
    if Fields[Result].Name = Name then
      Exit(Result);
    Dec(Result);
  end;
  Result := Length(Fields);
  SetLength(Fields, Result + 1);
  Fields[Result].Name := Name;
end;


procedure THeaderFields.SetHeader(Index: Integer; const Value: string);
begin
  if Fields[Index].Value = '' then
    Fields[Index].Value := Value
  else
    Fields[Index].Value := Fields[Index].Value + ';' + Value;
end;

function THeaderFields.GetHeader(const Name: string): string;
var
  cName: string;
  Index: Integer;
begin
  cName := CamelCase(Name);
  for Index := 0 to Length(Fields) - 1 do
  begin
    if Fields[Index].Name = cName then
      Exit(Fields[Index].Value);
  end;
  Result := '';
end;

function THeaderFields.HasHeader(const Name, Value: string): Boolean;
var
  Header: string;
  Index: Integer;
begin
  Header := GetHeader(Name);
  Index := System.Pos(Value, Header);
  while Index > 0 do
  begin
    if (Index = 1) or (Header[Index - 1] = ';') then
    begin
      Inc(Index, Length(Value));
      if (Index > Length(Header)) or (Header[Index] = ';') then
        Exit(True);
    end else begin
      Inc(Index, Length(Value));
    end;
    Index := System.Pos(Value, Header, Index);
  end;
  Result := False;
end;

{ THTTPClient }

constructor THTTPClient.Create;
begin
  FContentType := 'text/html; charset=UTF-8';
  FAccept := '*/*';
  FAcceptGZIP := True;
  FUserAgent := 'Mozilla/5.0 (' + TOSVersion.Name + ') Execute.HTTPClient/1.0';
  FCustomHeaders := TStringList.Create;
  FCustomHeaders.NameValueSeparator := ':';
  FHeader := TStringStream.Create;
end;

destructor THTTPClient.Destroy;
begin
  Close;
  FHeader.Free;
  FCustomHeaders.Free;
  inherited;
end;

function THTTPClient.AcceptEncoding: UTF8String;
begin
  if FAcceptGZIP then
    Result := 'Accept-Encoding: gzip'#13#10
  else
    Result := '';
end;

function THTTPClient.GetCustomHeaders: UTF8String;
var
  Lst: TStringList;
  Str: string;
begin
  Lst := TStringList.Create;
  try
    Lst.Assign(FCustomHeaders);
    SetCookies(Lst);
    if FAuthorization <> '' then
      Lst.Add('Authorization: ' + FAuthorization);
    Str := Trim(Lst.Text);
  finally
    Lst.Free;
  end;
  if Str = '' then
    Result := ''
  else begin
    Result := UTF8String(Str) + #13#10;
  end;
end;

procedure THTTPClient.SetCookies(Lst: TStrings);
var
  Value: string;
  Index: Integer;
  Exist: Integer;
  Found: Integer;
  Include: array of Integer;
  Count: Integer;
begin
  SetLength(Include, Length(FCookies));
  Count := 0;

  for Index := 0 to Length(FCookies) - 1 do
  begin
    if (FCookies[Index].Host <> FHost) and (FCookies[Index].Domain <> '') and UTF8EndsWith(FHost,FCookies[Index].Domain) then
    begin
      Include[Count] := Index;
      Inc(Count);
    end;
  end;

  for Index := 0 to Length(FCookies) - 1 do
  begin
    if FCookies[Index].Host = UTF8String(FHost) then
    begin
      Found := -1;
      for Exist := 0 to Count - 1 do
      begin
        if FCookies[Include[Exist]].Name = FCookies[Index].Name then
        begin
          Found := Exist;
          Break;
        end;
      end;
      if Found < 0 then
      begin
        Include[Count] := Index;
        Inc(Count);
      end else begin
        Include[Found] := Index;
      end;
    end;
  end;

  if Count = 0 then
    Exit;

  Value := '';
  for Exist := 0 to Count - 1 do
  begin
    if Value <> '' then
      Value := Value + '; ';
    Index := Include[Exist];
    Value := Value + string(FCookies[Index].Name) + '=' + string(FCookies[Index].Value);
  end;
  Lst.Add('Cookie: ' + Value);
end;

function THTTPClient.TimedOut: Boolean;
begin
  var Ticks := GetTickCount;
  Result := (Ticks  - FLastTick) div 1000 >= FTimeout;
end;

procedure THTTPClient.SendRequest(Req: TStream);
begin
  FHeader.Clear;
  FHeaders.Fields := nil;
//  FCookies := nil;

  if Assigned(FSocket) and (TimedOut or FSocket.Closed) then
  begin
  {$IFDEF DEBUG}AllocConsole;WriteLn('Closing');{$ENDIF}
    Close;
  end;

  if FSocket = nil then
  begin
    if FTLS then
    begin
      FSocket := TTinyTLS.Create();
    end else begin
      FSocket := TSocket.Create;
    end;
    FSocket.Connect(FHost, FPort);
  end;

  FSocket.SendStream(Req);
end;

procedure THTTPClient.DoRequest(Req, Rsp: TStream; Body: TStream = nil);
var
  Size: Integer;
begin
  try
    SendRequest(Req);
    if Body <> nil then
      FSocket.SendStream(Body);
    FSocket.ReadUntilSequence(FHeader, #13#10#13#10);
    {$IFDEF LOG_HTTP}
    WriteLn('[RESPONSE]');
    WriteLn(FHeader.DataString);
    WriteLn;
    {$ENDIF}
    ParseHeader;

    Size := StrToIntDef(FHeaders.GetHeader('Content-Length'), -1);
    if Size = -1 then
    begin
      if FHeaders.GetHeader('Transfer-Encoding') = 'chunked' then
      begin
        ReadChunks(Rsp);
      end else
      if FHeaders.GetHeader('Connection') <> 'close' then
        raise Exception.Create('No content-length')
      else begin
        FSocket.ReadUntilClosed(Rsp);
      end;
    end else begin
      FSocket.ReadStream(Rsp, Size);
    end;

    if FHeaders.HasHeader('Content-Encoding', 'gzip') then
    begin
      DecodeGZip(Rsp);
    end;

    {$IFDEF LOG_HTTP}
    WriteLn(StreamToString(Rsp, TEncoding.UTF8));
    WriteLn;
    {$ENDIF}

    if FHeaders.HasHeader('Connection', 'close') then
      Close
    else
      GetTimeOut;

  except
    Close;
    raise;
  end;
end;

procedure THTTPClient.Request(const Method, URL: UTF8String;
  Rsp: TStream; Body: TStream = nil);
var
  lURL: TURL;
  lReq: UTF8String;
  sReq: TMemoryStream;
begin
  lURL.Decode(URL);
  FHost := lURL.HostName;
  FPort := StrToInt(lURL.Port);
  SetTLS(lURL.Protocol = 'https');

  if Body = nil then
    lReq := ''
  else
    lReq := 'Content-Length: ' + AnsiString(IntToStr(Body.Size)) + #13#10;

  lReq := Method + ' ' + lURL.URI + ' HTTP/1.1'#13#10
        + 'Connection: ' + CONNECTION[FKeepAlive] + #13#10
        + 'Host: ' + FHost + #13#10
        + 'Content-Type: ' + ContentType + #13#10
        + lReq // Content-Length
        + 'Accept: '+ Accept + #13#10
        + AcceptEncoding
        + 'User-Agent: '+ UserAgent + #13#10
        + GetCustomHeaders
        + #13#10;
//  if lReq[Length(LReq) - 2] <> #10 then
//    lReq := lReq + #13#10;
{$IFDEF LOG_HTTP}
  AllocConsole;
  WriteLn('[HEADER]');
  WriteLn(lReq);
  WriteLn;
{$ENDIF}
{$IFDEF KEEP_HTTP}
  SendStr := string(lReq) + Body.ToString;
  RecvStr := '';
{$ENDIF}
{$IFDEF LOG_HTTP}
  if Body <> nil then
  begin
    WriteLn('[BODY]');
    WriteLn(Body.ToString);
    WriteLn;
  end;
{$ENDIF}
  sReq := TMemoryStream.Create;
  try
    sReq.Write(lReq[1], Length(lReq));
    DoRequest(sReq, Rsp, Body);
    {$IFDEF KEEP_HTTP}
      RecvStr := FHeader.DataString + StreamToString(Rsp, TEncoding.UTF8);
    {$ENDIF}
  finally
    sReq.Free;
  end;
end;

procedure THTTPClient.SetTLS(Value: Boolean);
begin
  if FTLS <> Value then
  begin
    Close;
    FTLS := Value;
  end;
end;

function THTTPClient.CookieIndex(const Name, Host: string): Integer;
begin
  Result := Length(FCookies) - 1;
  while Result >= 0 do
  begin
    if (string(FCookies[Result].Name) = Name) and (string(FCookies[Result].Host) = Host) then
      Exit(Result);
    Dec(Result);
  end;
  Result := Length(FCookies);
  SetLength(FCookies, Result + 1);
  FCookies[Result].Host := UTF8String(Host);
  FCookies[Result].Name := UTF8String(Name);
end;

procedure THTTPClient.ParseCookie(const Value: string);
// https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Set-Cookie
// <cookie-name>=<cookie-value>; Domain=<domain-value>; Secure; HttpOnly
var
  Idx: Integer;
  Val: string;
  Name: string;
  Index: Integer;
begin
{$IFDEF DEBUG_COOKIE}AllocConsole; WriteLn('ParseCookie(', Value, ')');{$ENDIF}
  Idx := 1;
  if not GetCSV(Value, Idx, Val) then
    Exit;
  if not GetPair(Val, Name, Val) then
    Exit;
  Index := CookieIndex(Name, FHost);
  FCookies[Index].Value := UTF8String(Val);
  FCookies[Index].Path  := '';
  FCookies[Index].Domain:= '';
  while GetCSV(Value, Idx, Val) do
  begin
    if GetPair(Val, Name, Val) then
    begin
      Name := CamelCase(Name);
      if Name = 'Path' then
        FCookies[Index].Path := UTF8String(Val)
      else
      if Name = 'Domain' then
        FCookies[Index].Domain := UTF8String(Val);
    end;
  end;
{$IFDEF DEBUG_COOKIE}AllocConsole; WriteLn('CookieCount = ', Length(FCookies));{$ENDIF}
end;

procedure THTTPClient.AddHeader(P: PAnsiChar; Start: Integer; var Index: Integer);
var
  Str: string;
  Name: string;
  Value: string;
begin
  SetString(Str, PAnsiChar(@P[Start]), Index - Start);
  Inc(Index);
  Name := CamelCase(Str);
  Value := '';
  Start := Index;
  while Index <= FHeader.Size do
  begin
    if P[Index] = #13 then
    begin
      if Index > Start then
      begin
        SetString(Str, PAnsiChar(@P[Start]), Index - Start);
        Str := Trim(Str);
        if Value = '' then
          Value := Str
        else
          Value := Value + ';' + Str;
        if P[Index + 2] = ' ' then
        begin
          Inc(Index, 2);
          Start := Index;
          Continue;
        end;
      end;
      Break;
    end;
    Inc(Index);
  end;
  if Name = 'Set-Cookie' then
    ParseCookie(Value)
  else begin
    FHeaders.Add(Name, Value);
  end;
end;

procedure THTTPClient.ParseHeader;
var
  P   : PAnsiChar;
  I,N : Integer;
begin
  FResponse := '';

  I := 0;
  P := FHeader.Memory;
  while I < FHeader.Size do
  begin
    if P[I] = #13 then
    begin
      SetString(FResponse, P, I);
      Break;
    end;
    Inc(I);
  end;

  while I < FHeader.Size do
  begin
    if P[I] = #10 then
    begin
      N := I + 1
    end else
    if P[I] = ':' then
    begin
      AddHeader(P, N, I);
    end;
    Inc(I);
  end;

  I := System.Pos(' ', FResponse);
  Val(Copy(FResponse, I + 1), FResponseCode, N);
end;

function THTTPClient.Post(const URL, Content: UTF8String): UTF8String;
var
  Stm: TPointerStream;
begin
  Stm := TPointerStream.Create(Pointer(Content) ,Length(Content));
  try
    Result := UTF8Request('POST', URL, Stm);
  finally
    Stm.Free;
  end;
end;

function THTTPClient.Put(const URL, Content: UTF8String): UTF8String;
var
  Stm: TPointerStream;
begin
  Stm := TPointerStream.Create(Pointer(Content) ,Length(Content));
  try
    Result := UTF8Request('PUT', URL, Stm);
  finally
    Stm.Free;
  end;
end;

procedure THTTPClient.Delete(const URL: UTF8String);
begin
  UTF8Request('DELETE', URL, nil);
end;

procedure THTTPClient.ReadChunks(Stream: TStream);
var
  Str : UTF8String;
  Size: Integer;
begin
// GetChunk size
  Str := FSocket.ReadLn;
  Size := StrToInt('$' + string(Str));
  while Size > 0 do
  begin
    FSocket.ReadStream(Stream, Size);
    Str := FSocket.ReadLn;
    if Str <> '' then
      raise Exception.Create('chunk CR/LF not found');
    Str := FSocket.ReadLn;
    Size := StrToInt('$' + string(Str));
  end;
  Str := FSocket.ReadLn;
  if Str <> '' then
    raise Exception.Create('Last chunk CR/LF not found');
end;

procedure THTTPClient.GetTimeout;
var
  Value, Val, Name: string;
  Idx: Integer;
begin
  FLastTick := GetTickCount;
  FTimeout := 5; // seconds, default
  Value := FHeaders.GetHeader('Keep-Alive');
  Idx := 1;
  while GetCSV(Value, Idx, Val, ',') do
  begin
    if GetPair(Val, Name, Val) then
    begin
      if Name = 'timeout' then
      begin
        FTimeout := StrToIntDef(Val, 5);
        Exit;
      end;
    end;
  end;
end;

function THTTPClient.UTF8Request(const Method, URL: UTF8String; Body: TStream): UTF8String;
var
  sRsp: TBytesStream;
  Enc : TEncoding;
  Head: Integer;
begin
  sRsp := TBytesStream.Create;
  try
    Request(Method, string(URL), sRsp, Body);
    Enc := nil;
    Head := TEncoding.GetBufferEncoding(sRsp.Bytes, Enc, TEncoding.UTF8);
    if Enc = TEncoding.UTF8 then
    begin
    {$IFDEF LOG_HTTP}WriteLn('Response is UTF8');{$ENDIF}
      SetLength(Result, sRsp.Size - Head);
      if Length(Result) > 0 then
        Move(sRsp.Bytes[Head], Result[1], Length(Result));
    end else begin
    {$IFDEF LOG_HTTP}WriteLn('Decode response to UTF8');{$ENDIF}
      Result := UTF8String(Enc.GetString(sRsp.Bytes, Head, sRsp.Size - Head));
    end;
  finally
    sRsp.Free;
  end;
end;

procedure THTTPClient.Close;
begin
  FreeAndNil(FSocket);
end;

function THTTPClient.Get(const URL: UTF8String): UTF8String;
begin
  Result := UTF8Request('GET', URL, nil);
end;

initialization
{$IFDEF DEBUG}
  Assert(UTF8Pos('://', 'http://hello') = 5);
  Assert(UTF8LowerCase('Http') = 'http');
  Assert(UTF8EndsWith('execute.fr', '.fr'));
{$ENDIF}
end.

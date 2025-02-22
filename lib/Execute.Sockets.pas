unit Execute.Sockets;

{
   Delphi Socket implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}


interface

uses
  Winapi.Windows,
  Winapi.Winsock,
  System.SysUtils,
  System.Classes;

type
  TByteBuffer = record
    Data : TBytes;
    Count: Integer;
    Start: Integer;
    procedure Clear;
    function Left: Integer;
    function Trim: Integer;
    function IndexOf(const Str: AnsiString; var StartPos: Integer): Integer;
    procedure Consume(Quantity: Integer);
  end;

  ESocketError = class(Exception)
    constructor Create(const Func: string);
  end;

  EClosedSocketError = class(ESocketError)
  end;

  TSocketHandle = Winapi.Winsock.TSocket;

  TSocket = class
  private
    FHost: UTF8String;
    FRecv: TByteBuffer;
    FHandle: TSocketHandle;
    class constructor Create;
    function ReadMore: Integer;
    procedure ReadMemoryStream(Stream: TMemoryStream; Size: Integer);
  public
    constructor Create;
    function Connect(const Host: UTF8String; Port: Integer; Timeout: Integer = 0): Integer; virtual;
    function Closed: Boolean; virtual;
    function Read(var Data; Size: Integer; Raw: Boolean = False): Integer; virtual;
    function Write(const Data; Size: Integer; Raw: Boolean = False): Integer; virtual;
    function WriteAll(const Data; Size: Integer; Raw: Boolean = False): Boolean;
    procedure SendStream(Stream: TStream);
    procedure ReadStream(Stream: TStream; Size: Integer);
    procedure ReadUntilSequence(Stream: TStream; const Sequence: AnsiString);
    procedure ReadUntilClosed(Stream: TStream);
    function ReadLn(Max: Integer = 1024): UTF8String;
    property Host: UTF8String read FHost write FHost;
  end;

implementation

const
  LIB_NAME = 'ws2_32.dll';

  INVALID_SOCKET_HANDLE = TSocketHandle(Winapi.Winsock.INVALID_SOCKET);

type
  PAddrInfo = ^TAddrInfo;
  TAddrInfo = record
    ai_flags     : Integer;
    ai_family    : Integer;
    ai_socktype  : Integer;
    ai_protocol  : Integer;
    ai_addrlen   : Integer;
    ai_canonname : PAnsiChar;
    ai_addr      : PSockAddr;
    ai_next      : PAddrInfo;
  end;

function getaddrinfo(node, service: UTF8String; const hints: TAddrInfo; var Result: PAddrInfo): Integer; stdcall; external LIB_NAME;
procedure freeaddrinfo(ai: PAddrInfo); stdcall; external LIB_NAME;

function GetAddrList(const Host, Service: UTF8String): TArray<Integer>;
var
  Hints: TAddrInfo;
  Infos: PAddrInfo;
  Info : PAddrInfo;
  Count: Integer;
  Addr : Integer;
  Index: Integer;
  Found: Boolean;
  Ent  : PHostEnt;
begin
  Result := nil;
  FillChar(Hints, SizeOf(Hints), 0);
  Hints.ai_family := AF_INET;
  Count := 0;
  if getaddrinfo(Host, Service, Hints, Infos) = 0 then
  try
    Info := Infos;
    while Info <> nil do
    begin
      if Info.ai_family = AF_INET then
      begin
        Addr := Info.ai_addr.sin_addr.S_addr;
        Found := False;
        for Index := 0 to Count - 1 do
        begin
          if Result[Index] = Addr then
          begin
            Found := True;
            Break;
          end;
        end;
        if Found = False then
        begin
          SetLength(Result, Count + 1);
          Result[Count] := Addr;
          Inc(Count);
        end;
      end;
      Info := Info.ai_next;
    end;
  finally
    freeaddrinfo(Infos);
  end;
  if Count = 0 then
  begin
    Ent := gethostByName(PAnsiChar(Host));
    if Ent <> nil then
    begin
      SetLength(Result, Count + 1);
      Result[Count] := PInteger(Ent.h_addr_list)^;
    end;
  end;
end;

{ TByteBuffer }

procedure TByteBuffer.Clear;
begin
  SetLength(Data, 2048);
  Count := 0;
  Start := 0;
end;

procedure TByteBuffer.Consume(Quantity: Integer);
begin
  Dec(Count, Quantity);
  if Count = 0 then
    Start := 0
  else begin
    Inc(Start, Quantity);
  end;
end;

function TByteBuffer.IndexOf(const Str: AnsiString; var StartPos: Integer): Integer;
var
  Index: Integer;
  Len: Integer;
begin
  Len := Length(Str);
  for Index := StartPos to Count - Len do
  begin
    if CompareMem(@Data[Start + Index], Pointer(Str), Len) then
      Exit(Index);
  end;
  Result := -1;
end;

function TByteBuffer.Left: Integer;
begin
  Result := Length(Data) - Start - Count;
end;

function TByteBuffer.Trim: Integer;
begin
  if (Count > 0) and (Start > 0) then
  begin
    Move(Data[Start], Data[0], Count);
    Start := 0;
  end;
  Result := Count;
end;

{ ESocketError }

constructor ESocketError.Create(const Func: string);
begin
  inherited Create('WINSOCK Error #' + IntToHex(WSAGetLastError, 8) + ' on function ' + Func);
end;

{ TSocket }

class constructor TSocket.Create;
var
  wsa: TWSAData;
begin
  WSAStartup($202, wsa);
end;

constructor TSocket.Create;
begin
  FHandle := INVALID_SOCKET_HANDLE
end;

procedure TSocket.SendStream(Stream: TStream);
var
  All: Integer;
  Ptr: PByte;
  Buf: TBytes;
  Len: Integer;
  Idx: Integer;
  Cnt: Integer;
begin
  All := Stream.Size;
  while All > 0 do
  begin
    Len := All;
    if Stream is TMemoryStream then
    begin
      Ptr := TMemoryStream(Stream).Memory;
    end else begin
      if Len > 8192 then
        Len := 8192;
      if Buf = nil then
      begin
        Stream.Position := 0;
        SetLength(Buf, Len);
      end;
      Stream.Read(Buf[0], Len);
      Ptr := PByte(Buf);
    end;
    Dec(All, Len);
    Idx := 0;
    while Idx < Len do
    begin
      Cnt := Write(Ptr[Idx], Len - Idx);
      Inc(Idx, Cnt);
    end;
  end;
end;

function TSocket.ReadMore: Integer;
begin
  var Left := FRecv.Left;
  if Left = 0 then
  begin
    Left := FRecv.Trim;
    if Left = 0 then
      Exit(0);
  end;
  Result := Read(FRecv.Data[FRecv.Start + FRecv.Count], Left);
  Inc(FRecv.Count, Result);
end;

procedure TSocket.ReadMemoryStream(Stream: TMemoryStream; Size: Integer);
var
  P: PByte;
  L: Integer;
  N: Integer;
begin
  L := Stream.Position;
  Stream.Size := L + Size;
  Stream.Position := Stream.Size;
  P := Stream.Memory;
  Inc(P, L);
  L := 0;
  N := FRecv.Count;
  if N > 0 then
  begin
    if N > Size then
      N := Size;
    Move(FRecv.Data[FRecv.Start], P[0], N);
    FRecv.Consume(N);
    L := N;
  end;
  while L < Size do
  begin
    N := Read(P[L], Size - L);
    Inc(L, N);
  end;
end;

procedure TSocket.ReadStream(Stream: TStream; Size: Integer);
var
  N: Integer;
begin
  if Stream is TMemoryStream then
    ReadMemoryStream(TMemoryStream(Stream), Size)
  else begin
    while Size > 0 do
    begin
      N := FRecv.Count;
      if N = 0 then
        N := ReadMore;
      if N > Size then
        N := Size;
      Stream.Write(FRecv.Data[FRecv.Start], N);
      FRecv.Consume(N);
      Dec(Size, N);
    end;
  end;
end;

procedure TSocket.ReadUntilSequence(Stream: TStream; const Sequence: AnsiString);
var
  Start: Integer;
  Index: Integer;
begin
  Start := 0;
  Index := FRecv.IndexOf(Sequence, Start);
  while Index < 0 do
  begin
    if FRecv.Count > 1024 + Length(Sequence) then
    begin
      Stream.Write(FRecv.Data[FRecv.Start], 1024);
      Move(FRecv.Data[FRecv.Start + 1024], FRecv.Data[0], FRecv.Count - 1024);
      FRecv.Start := 0;
      Dec(FRecv.Count, 1024);
      Start := 0;
    end;
    ReadMore();
    Index := FRecv.IndexOf(Sequence, Start);
  end;
  Inc(Index, Length(Sequence));
  Stream.Write(FRecv.Data[FRecv.Start], Index);
  FRecv.Consume(Index);
end;

procedure TSocket.ReadUntilClosed(Stream: TStream);
begin
  repeat
    if FRecv.Count > 0 then
    begin
      Stream.Write(FRecv.Data[FRecv.Start], FRecv.Count);
      FRecv.Count := 0;
      FRecv.Start := 0;
    end;
    ReadMore;
  until FRecv.Count = 0;
end;

function TSocket.ReadLn(Max: Integer = 1024): UTF8String;
var
  Len: Integer;
  Start: Integer;
  CRLF: Integer;
begin
  Result := '';
  Len := 0;
  Start := 0;
  CRLF := FRecv.IndexOf(#13#10, Start);
  while CRLF < 0 do
  begin
    if Len + FRecv.Count > Max then
      raise Exception.Create('Line too long');
    if FRecv.Left = 0 then
    begin
      SetLength(Result, Len + FRecv.Count);
      Move(FRecv.Data[FRecv.Start], Result[Len + 1], FRecv.Count);
      Inc(Len, FRecv.Count);
      FRecv.Consume(FRecv.Count);
    end;
    ReadMore();
    CRLF := FRecv.IndexOf(#13#10, Start);
  end;
  SetLength(Result, Len + CRLF);
  if CRLF > 0 then
    Move(FRecv.Data[FRecv.Start], Result[Len + 1], CRLF);
  FRecv.Consume(CRLF + 2);
end;

function TSocket.Connect(const Host: UTF8String; Port: Integer; Timeout: Integer = 0): Integer;
var
  AddrList: TArray<Integer>;
  mode: Integer;
  SockAddr: TSockAddr;
  Index   : Integer;
  fdset: record         // less memory than Winsock one
    count : u_int;
    handle: TSocketHandle;
  end;
  time : timeval;
begin
  FRecv.Clear;

  FHost := Host;

  AddrList := GetAddrList(FHost, UTF8String(IntToStr(Port)));
  if Length(AddrList) = 0 then
    raise ESocketError.Create('getaddrinfo on host ' + Host);

  if FHandle = INVALID_SOCKET_HANDLE then
  begin
    FHandle := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if FHandle = INVALID_SOCKET_HANDLE then
      raise ESocketError.Create('socket');
  end;

  if Timeout > 0 then
  begin
  // non blocking mode
    mode := 1;
    ioctlsocket(FHandle, FIONBIO, mode);
  end;

  FillChar(SockAddr, SizeOf(SockAddr), 0);
  SockAddr.sin_family := AF_INET;
  SockAddr.sin_port := htons(Port);
  for Index := 0 to Length(AddrList) - 1 do
  begin
    SockAddr.sin_addr.S_addr := AddrList[Index];
    Result := Winapi.Winsock.connect(FHandle, SockAddr, SizeOf(SockAddr));
    if (Result = SOCKET_ERROR) and (Timeout > 0) and (WSAGetLastError = WSAEWOULDBLOCK) then
    begin
      fdset.count := 1;
      fdset.handle := FHandle;
      time.tv_sec := Timeout div 1000;
      time.tv_usec := (Timeout mod 1000) * 1000;
      if select(0, nil, @fdset, nil, @time) = 1 then
      begin
      // blocking mode
        mode := 0;
        ioctlsocket(FHandle, FIONBIO, mode);
        Result := 0;
      end;
    end;

    if Result = 0 then
    begin
//      OnConnect;
      Exit;
    end;
  end;
  raise ESocketError.Create('connect');
end;

function TSocket.Closed: Boolean;
var
  fdwrite, fderror: record         // less memory than Winsock one
    count : u_int;
    handle: TSocketHandle;
  end;
  time : timeval;
begin
  if FHandle = INVALID_SOCKET_HANDLE then
    Exit(True);
  fdwrite.count := 1;
  fdwrite.handle := FHandle;
  fderror := fdwrite;
  time.tv_sec := 0;
  time.tv_usec := 500;
  var count := select(0, nil, @fdwrite, @fderror, @time);
  Result := (count <> 1) or (fdwrite.count  <> 1) or (fderror.count <> 0);
end;

function TSocket.Read(var Data; Size: Integer; Raw: Boolean): Integer;
begin
  Result := recv(FHandle, Data, Size, 0);
  if Result <= 0 then
    raise EClosedSocketError.Create('recv');
end;

function TSocket.Write(const Data; Size: Integer; Raw: Boolean): Integer;
begin
  Result := send(FHandle, Data, Size, 0);
  if Result = 0 then
    raise EClosedSocketError.Create('send');
  if Result < 0 then
    raise ESocketError.Create('send');
end;

function TSocket.WriteAll(const Data; Size: Integer; Raw: Boolean = False): Boolean;
begin
  var P: PByte := @Data;
  while Size > 0 do
  begin
    var Count := Write(P^, Size, Raw);
    if Count <= 0 then
      Exit(False);
    Inc(P, Count);
    Dec(Size, Count);
  end;
  Result := True;
end;

end.

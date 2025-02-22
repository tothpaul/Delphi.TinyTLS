unit Execute.TinyTLS.Extensions;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface

uses
  System.SysUtils,
  Execute.TinyTLS.Types;

type
  // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
  TExtensionType = (
    ServerName           =     0,  // [RFC6066][RFC9261]
    SupportedGroups      =    10,  // [RFC8422][RFC7919]
    ECPointFormats       =    11,  // [RFC8422]
    SignatureAlgorithms  =    13,  // [RFC8446]
    EncryptThenMac       =    22,
    ExtendedMasterSecret =    23,  // [RFC7627]
    SessionTicketTLS     =    35,  // [RFC5077][RFC8447]
    SupportedVersions    =    43,
    PSKeyExchangeModes   =    45,
    PostHandshakeAuth    =    49,
    KeyShare             =    51,
    RenegotiationInfo    = 65281   // [RFC5746]
  );

  TNameType = (
    HostName = 0
  );

  TServerNameExtension = packed record
  private
    FSize: Word;
    function GetSize: Word;
  public
    NameType: TNameType;
  private
    FNameLen: Word;
    FName: AnsiChar;
    function GetName: UTF8String;
    procedure SetName(const Value: UTF8String);
    function GetNameLength: Word;
  public
    class function SizeFor(const AHostName: UTF8String): Integer; static;
    property Size: Word read GetSize;
    property Name: UTF8String read GetName write SetName;
    property NameLength: Word read GetNameLength;
  end;
  PServerNameExtension = ^TServerNameExtension;

  TRenegotiationInfoExtension = packed record
    Len: Byte;
  end;
  PRenegotiationInfoExtension = ^TRenegotiationInfoExtension;

  TSupportedGroup = TCurveName;

  TSupportedGroupsExtension = packed record
  private
    FSize: Word;
    FGroups: array[Word] of Word;
    function GetSize: Word;
    function GetCount: Word;
    procedure SetCount(Value: Word);
    function GetGroup(Index: Integer): TSupportedGroup;
    procedure SetGroup(Index: Integer; Value: TSupportedGroup);
  public
    class function SizeFor(const Groups: TArray<TSupportedGroup>): Integer; static;
    function SetGroups(const Value: TArray<TSupportedGroup>): Integer;
    function Supports(Value: TSupportedGroup): Boolean;
    property Size: Word read GetSize;
    property Count: Word read GetCount write SetCount;
    property Groups[Index: Integer]: TSupportedGroup read GetGroup write SetGroup;
  end;
  PSupportedGroupsExtension = ^TSupportedGroupsExtension;

  TECPointFormat = (
    uncompressed = 0,
    ansiX962_compressed_prime = 1,
    ansiX962_compressed_char2 = 2
  );

  TECPointFormatsExtension = packed record
    Count: Byte;
    Formats: array[Byte] of TEcPointFormat;
    function SetFormats(const Formats: TArray<TECPointFormat>): Integer;
  end;
  PECPointFormatsExtension = ^TECPointFormatsExtension;

  TSignatureAndHashAlgorithm = packed record
  private
    function GetSignatureScheme: TSignatureScheme;
    procedure SetSignatureScheme(Value: TSignatureScheme);
  public
    Hash: THashAlgorithm;
    Signature: TSignatureAlgorithm;
    property SignatureScheme: TSignatureScheme read GetSignatureScheme write SetSignatureScheme;
  end;
  PSignatureAndHashAlgorithm = ^TSignatureAndHashAlgorithm;

  TSignatureAlgorithmsExtension = record
  private
    FSize: Word;
    function GetCount: Word;
    procedure SetCount(Value: Word);
    function GetSize: Word;
  public
    Signatures: array[Word] of TSignatureAndHashAlgorithm;
    class function SizeFor(const Values: TArray<TSignatureScheme>): Integer; static;
    function SetSignatureSchemes(const Values: TArray<TSignatureScheme>): Integer;
    property Count: Word read GetCount write SetCount;
    property Size: Word read GetSize;
  end;
  PSignatureAlgorithmsExtension = ^TSignatureAlgorithmsExtension;

  TClientSupportedVersionsExtension = packed record
  private
    FBytes: Byte;
    procedure SetCount(Value: Byte);
  public
    Versions: array[Word] of Word;
    class function SizeFor(VersionCount: Integer): Integer; static;
    property Count: Byte write SetCount;
    property Bytes: Byte read FBytes;
  end;
  PClientSupportedVersionsExtension = ^TClientSupportedVersionsExtension;

  TPSKeyExchangeModes = packed record
    Count: Byte;
    Modes: array[Word] of Byte;
    class function SizeFor(ModeCount: Integer): Integer; static;
  end;
  PPSKeyExchangeModes = ^TPSKeyExchangeModes;

  TKeyShareExtension = packed record
  private
    FCurve: Word; // Swap(TCurveName)
    FKeyLen: Word;
    FKey: array[Word] of Byte;
    function GetCurve: TCurveName;
  public
    function SetKey(Curve: TCurveName; const Key: TBytes): Integer;
    property Curve: TCurveName read GetCurve;
    function GetKey: TBytes;
  end;
  PKeyShareExtension = ^TKeyShareExtension;

  TClientKeyShareExtension = packed record
  private
    FSize: Word;
  public
    function Size: Word;
  public
    KeyShare: TKeyShareExtension;
  public
    function SetKey(Curve: TCurveName; const Key: TBytes): Integer;
  end;
  PClientKeyShareExtension = ^TClientKeyShareExtension;

  TExtensionHeader = packed record
  private
    FExtensionType : Word;
    FLength: Word;
    function GetExtensionType: TExtensionType;
    procedure SetExtensionType(Value: TExtensionType);
    function GetLength: Word; inline;
    procedure SetLength(Value: Word); inline;
  public
    property ExtensionType: TExtensionType read GetExtensionType write SetExtensionType;
    property Length: Word read GetLength write SetLength;
    function Payload: Pointer;
  end;
  PExtensionHeader = ^TExtensionHeader;

  TExtensionList = packed record
  private
    FSize: Word;
    function GetSize: Word; inline;
    procedure SetSize(Value: Word); inline;
    function GetItem(Index: Integer): PExtensionHeader;
  public
    Data: array[Word] of Byte;
    class function SizeFor(Size: Integer): Integer; static;
    function ItemOffset(Index: Integer): Word;
    property Size: Word read GetSize write SetSize;
    property Items[Index: Integer]: PExtensionHeader read GetItem; default;
  end;
  PExtensionList = ^TExtensionList;

  TSHASignature = array[0..255] of Byte;

  TCertificateVerify = packed record
  public
    Algorithm: TSignatureAndHashAlgorithm;
  private
    FSize: Word;
    function GetSize: Word;
    procedure SetSize(Value: Word);
  public
    Signature: TSHASignature;  // RSA only ?
    property Size: Word read GetSize write SetSize;
  end;
  PCertificateVerify = ^TCertificateVerify;

implementation

{ TServerNameExtension }

class function TServerNameExtension.SizeFor(const AHostName: UTF8String): Integer;
begin
  Result := SizeOf(TServerNameExtension) - 1 {FName} + Length(AHostName);
end;

function TServerNameExtension.GetName: UTF8String;
begin
  SetLength(Result, GetNameLength);
  Move(FName, Result[1], Length(Result));
end;

function TServerNameExtension.GetNameLength: Word;
begin
  Result := Swap(FNameLen);
end;

function TServerNameExtension.GetSize: Word;
begin
  Result := Swap(FSize);
end;

procedure TServerNameExtension.SetName(const Value: UTF8String);
begin
  FSize := Swap(SizeOf(Self) - SizeOf(FSize) - SizeOf(FName) + Length(Value));
  NameType := HostName;
  FNameLen := Swap(Length(Value));
  Move(Value[1], FName, Length(Value));
end;

{ TSupportedGroupsExtension }

class function TSupportedGroupsExtension.SizeFor(const Groups: TArray<TSupportedGroup>): Integer;
begin
  Result := Length(Groups);
  if Result > 0 then
  begin
    Result := SizeOf(Word { FSize }) + Result * SizeOf(Word {TSupportedGroup});
  end;
end;

function TSupportedGroupsExtension.Supports(Value: TSupportedGroup): Boolean;
begin
  for var I := 0 to Count - 1 do
    if Groups[I] = Value then
      Exit(True);
  Result := False;
end;

function TSupportedGroupsExtension.GetSize: Word;
begin
  Result := Swap(FSize);
end;

function TSupportedGroupsExtension.GetCount: Word;
begin
  Result := Swap(FSize) div 2;
end;

procedure TSupportedGroupsExtension.SetCount(Value: Word);
begin
  FSize := Swap(2 * Value);
end;

function TSupportedGroupsExtension.GetGroup(Index: Integer): TSupportedGroup;
begin
  Result := TSupportedGroup(Swap(FGroups[Index]));
end;

procedure TSupportedGroupsExtension.SetGroup(Index: Integer;
  Value: TSupportedGroup);
begin
  FGroups[Index] := Swap(Ord(Value));
end;

function TSupportedGroupsExtension.SetGroups(
  const Value: TArray<TSupportedGroup>): Integer;
begin
  Count := Length(Value);
  Result := Count;
  if Result > 0 then
    Result := SizeOf(FSize) + Count * SizeOf(TSupportedGroup);
  for var I := 0 to Length(Value) - 1 do
      Groups[I] := Value[I];
end;

{ TECPointFormatsExtension }

function TECPointFormatsExtension.SetFormats(
  const Formats: TArray<TECPointFormat>): Integer;
begin
  Result := SizeOf(Count) + Length(Formats);
  Count := Length(Formats);
  Move(Formats[0], Self.Formats[0], Count);
end;

{ TSignatureAndHashAlgorithm }

function TSignatureAndHashAlgorithm.GetSignatureScheme: TSignatureScheme;
begin
  Result := TSignatureScheme(Swap(Word(Self)));
end;

procedure TSignatureAndHashAlgorithm.SetSignatureScheme(Value: TSignatureScheme);
begin
  Word(Self) := Swap(Ord(Value));
end;

{ TSignatureAlgorithmsExtension }

function TSignatureAlgorithmsExtension.GetCount: Word;
begin
  Result := Swap(FSize) div 2;
end;

function TSignatureAlgorithmsExtension.GetSize: Word;
begin
  Result := Swap(FSize);
end;

procedure TSignatureAlgorithmsExtension.SetCount(Value: Word);
begin
  FSize := Swap(2 * Value);
end;

class function TSignatureAlgorithmsExtension.SizeFor(const Values: TArray<TSignatureScheme>): Integer;
begin
  Result := Length(Values);
  if Result > 0 then
  begin
    Result := 2 + 2 * Result;
  end;
end;

function TSignatureAlgorithmsExtension.SetSignatureSchemes(const Values: TArray<TSignatureScheme>): Integer;
begin
  Count := Length(Values);
  Result := Count;
  if Result > 0 then
    Result := 2 + 2 * Result;
  for var I := 0 to Length(Values) - 1 do
    Signatures[I].SignatureScheme := Values[I];
end;

{ TClientSupportedVersionsExtension }

procedure TClientSupportedVersionsExtension.SetCount(Value: Byte);
begin
  FBytes := 2 * Value;
end;

class function TClientSupportedVersionsExtension.SizeFor(VersionCount: Integer): Integer;
begin
  Result := 1 + VersionCount * SizeOf(Word);
end;

{ TPSKeyExchangeModes }

class function TPSKeyExchangeModes.SizeFor(ModeCount: Integer): Integer;
begin
  Result := 1 + ModeCount * SizeOf(Byte);
end;

{ TKeyShareExtension }

function TKeyShareExtension.GetKey: TBytes;
begin
  var L := Swap(FKeyLen);
  SetLength(Result, L);
  if L > 0 then
    Move(FKey, Result[0], L);
end;

function TKeyShareExtension.GetCurve: TCurveName;
begin
  Result := TCurveName(Swap(FCurve));
end;

function TKeyShareExtension.SetKey(Curve: TCurveName; const Key: TBytes): Integer;
begin
  FCurve := Swap(Ord(Curve));
  FKeyLen := Swap(Length(Key));
  Move(Key[0], FKey, Length(Key));
  Result := SizeOf(FCurve) + SizeOf(FKeyLen) + Length(Key);
end;

{ TClientKeyShareExtension }

function TClientKeyShareExtension.Size: Word;
begin
  Result := Swap(FSize);
end;

function TClientKeyShareExtension.SetKey(Curve: TCurveName;
  const Key: TBytes): Integer;
begin
   Result := KeyShare.SetKey(Curve, Key);
   FSize := Swap(Result);
   Inc(Result, SizeOf(FSize));
end;

{ TExtensionHeader }

function TExtensionHeader.GetExtensionType: TExtensionType;
begin
  Result := TExtensionType(Swap(FExtensionType));
end;

procedure TExtensionHeader.SetExtensionType(Value: TExtensionType);
begin
  FExtensionType := Swap(Ord(Value));
end;

function TExtensionHeader.GetLength: Word;
begin
  Result := Swap(FLength);
end;

procedure TExtensionHeader.SetLength(Value: Word);
begin
  FLength := Swap(Value);
end;

function TExtensionHeader.Payload: Pointer;
begin
  Result := @PByte(@Self)[SizeOf(Self)];
end;

{ TExtensionList }

class function TExtensionList.SizeFor(Size: Integer): Integer;
begin
  Result := Size;
  if Result > 0 then
    Inc(Result, 2);
end;

function TExtensionList.ItemOffset(Index: Integer): Word;
begin
  Result := 0;
  for var J := 0 to Index - 1 do
  begin
    Inc(Result, SizeOf(TExtensionHeader) + PExtensionHeader(@Data[Result]).Length);
  end;
end;

function TExtensionList.GetSize: Word;
begin
  Result := Swap(FSize);
end;

procedure TExtensionList.SetSize(Value: Word);
begin
  FSize := Swap(Value);
end;

function TExtensionList.GetItem(Index: Integer): PExtensionHeader;
begin
  Result := @Data[ItemOffset(Index)];
end;

{ TCertificateVerify }

function TCertificateVerify.GetSize: Word;
begin
  Result := Swap(FSize);
end;

procedure TCertificateVerify.SetSize(Value: Word);
begin
  FSize := Swap(Value);
end;

end.

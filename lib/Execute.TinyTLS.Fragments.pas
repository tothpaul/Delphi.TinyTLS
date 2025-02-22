unit Execute.TinyTLS.Fragments;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface
{$POiNTERMATH ON}
uses
  System.SysUtils,
  Execute.TinyTLS.Types,
  Execute.TinyTLS.Extensions;

type
  TServerHello = packed record
  private
    function GetSessionID: TBytes;
    procedure SetSessionID(Value: TBytes);
    function GetCipher: TCipherSuiteTag;
    procedure SetCipher(Value: TCipherSuiteTag);
    function GetCompression: TCompressionMethodTag;
    procedure SetCompression(Value: TCompressionMethodTag);
  public
    ProtocolVersion: TProtocolVersion;
    Random         : TRandom;
    SessionIDLen   : Byte;
    function Length(Size: Cardinal): Cardinal;
    property SessionID: TBytes read GetSessionID write SetSessionID;
    property Cipher: TCipherSuiteTag read GetCipher write SetCipher;
    property Compression: TCompressionMethodTag read GetCompression write SetCompression;
    function HasExtensions(HandshakeSize: Cardinal): Boolean;
    function ExtensionList: PExtensionList;
  end;
  PServerHello = ^TServerHello;

  TCurveType = (
    NamedCurve = 3
  );

  TServerKeyExchange = packed record
    CurveType: TCurveType;
  private
    FNamedCurve: Word;
    function GetNamedCurve: TCurveName;
    procedure SetNamedCurve(Value: TCurveName);
    function GetPublicKey: TBytes;
    procedure SetPublicKey(const Value: TBytes);
    function GetHashAlgorithm: THashAlgorithm;
    procedure SetHashAlgorithm(Value: THashAlgorithm);
    function GetSignatureAndHashAlgorithm: TSignatureAndHashAlgorithm;
    function GetSignatureScheme: TSignatureScheme;
    procedure SetSignatureScheme(Value: TSignatureScheme);
    function GetSignatureSize: Word;
    function GetSignature: TBytes;
    procedure SetSignature(const Value: TBytes);
  public
    property NamedCurve: TCurveName read GetNamedCurve write SetNamedCurve;
  public
    PublicKeySize: Byte;
    class function SizeFor(const Key, Signature: TBytes): Integer; static;
    procedure CheckSize(Size: Word);
    property PublicKey: TBytes read GetPublicKey write SetPublicKey;
    property HashAlgorithm: THashAlgorithm read GetHashAlgorithm write SetHashAlgorithm;
    property SignatureAndHashAlgorithm: TSignatureAndHashAlgorithm read GetSignatureAndHashAlgorithm; // WARNING ! READONLY !
    property SignatureScheme: TSignatureScheme read GetSignatureScheme write SetSignatureScheme;
    property SignatureSize: Word read GetSignatureSize;
    property Signature: TBytes read GetSignature write SetSignature;
  end;
  PServerKeyExchange = ^TServerKeyExchange;

  TCertificateRequest = packed record
  public
    CertificateTypesCount: Byte;
  private
    function Payload(Index: Integer): Pointer;
    function GetCertificateType(Index: Integer): TClientCertificateType;
    procedure SetCertificateType(Index: Integer; Value: TClientCertificateType);
    function GetSignatureAndHashAlgorithmCount: Word;
    procedure SetSignatureAndHashAlgorithmCount(Value: Word);
    procedure SetSignatureAndHashAlgorithm(Index: Integer; const Value: TSignatureAndHashAlgorithm);
    function GetSignatureAndHashAlgorithm(Index: Integer): TSignatureAndHashAlgorithm;
    function GetDistinguishedNames: TArray<UTF8String>;
  public
    class function SizeFor(const CertificateTypes: TArray<TClientCertificateType>; const SignatureSchemes: TArray<TSignatureScheme>; const EncodedDistinguishedNames: TBytes): Integer; static;
    procedure SetCertificateTypes(const Values: TArray<TClientCertificateType>);
    function GetCertificateTypes: TArray<TClientCertificateType>;
    procedure SetSignatureSchemes(const Values: TArray<TSignatureScheme>);
    function GetSignatureSchemes: TArray<TSignatureScheme>;
    class function EncodeDistinguishedNames(const Values: TArray<UTF8String>): TBytes; static;
    procedure SetEncodedDistinguishedNames(const Values: TBytes);
    property CertificateTypes[Index: Integer]: TClientCertificateType read GetCertificateType write SetCertificateType;
    property SignatureAndHashAlgorithmCount: Word read GetSignatureAndHashAlgorithmCount write SetSignatureAndHashAlgorithmCount;
    property SignatureAndHashAlgorithm[Index: Integer]: TSignatureAndHashAlgorithm read GetSignatureAndHashAlgorithm write SetSignatureAndHashAlgorithm;
    property DistinguishedNames: TArray<UTF8String> read GetDistinguishedNames;
  end;
  PCertificateRequest = ^TCertificateRequest;

  TClientHello = packed record
  private
    function GetSessionID: TBytes;
    procedure SetSessionID(const Value: TBytes);
  public
    ProtocolVersion: TProtocolVersion;
    Random         : TRandom;
    SessionIDLen   : Byte;
  //SessionID
  //CipherList
  //CompressionList
  //Extensions
    function CipherList: PCipherList;
    function CompressionList: PCompressionList;
    function HasExtensions(HandshakeSize: Cardinal): Boolean;
    function ExtensionList: PExtensionList;
    property SessionID: TBytes read GetSessionID write SetSessionID;
  end;
  PClientHello = ^TClientHello;

implementation

{ TServerHello }

function TServerHello.Length(Size: Cardinal): Cardinal;
begin
  Result := SizeOf(Self) + SessionIDLen + 2 + 1;
  if Result < Size then
    Result := Result + 2 + ExtensionList.Size;
end;

function TServerHello.GetSessionID: TBytes;
begin
  SetLength(Result, SessionIDLen);
  if SessionIDLen > 0 then
    Move(PByte(@Self)[SizeOf(Self)], Result[0], SessionIDLen);
end;

procedure TServerHello.SetSessionID(Value: TBytes);
begin
  SessionIDLen := System.Length(Value);
  if SessionIDLen > 0 then
    Move(Value[0], PByte(@Self)[SizeOf(Self)], SessionIDLen);
end;

function TServerHello.GetCipher: TCipherSuiteTag;
begin
  Result := TCipherSuiteTag(Swap(PWord(@PByte(@Self)[SizeOf(Self) + SessionIDLen])^));
end;

procedure TServerHello.SetCipher(Value: TCipherSuiteTag);
begin
  PWord(@PByte(@Self)[SizeOf(Self) + SessionIDLen])^ := Swap(Ord(Value));
end;

function TServerHello.GetCompression: TCompressionMethodTag;
begin
  Result := TCompressionMethodTag(PByte(@Self)[SizeOf(Self) + SessionIDLen + 2]);
end;

procedure TServerHello.SetCompression(Value: TCompressionMethodTag);
begin
  PByte(@Self)[SizeOf(Self) + SessionIDLen + 2] := Ord(Value);
end;

function TServerHello.HasExtensions(HandshakeSize: Cardinal): Boolean;
begin
  Result := HandshakeSize > SizeOf(Self) + SessionIDLen + 2 { Cipher } + 1 { Compression };
end;

function TServerHello.ExtensionList: PExtensionList;
begin
  Result := @PByte(@Self)[SizeOf(Self) + SessionIDLen + 2 { Cipher } + 1 { Compression }];
end;

{ TServerKeyExchange }

procedure TServerKeyExchange.CheckSize(Size: Word);
begin
  if (Size < SizeOf(TServerKeyExchange))
  or (Size < SizeOf(TServerKeyExchange) + PublicKeySize + SizeOf(TSignatureAndHashAlgorithm) + SizeOf(Word))
  or (Size <> SizeOf(TServerKeyExchange) + PublicKeySize + SizeOf(TSignatureAndHashAlgorithm) + SizeOf(Word) + SignatureSize) then
    raise Exception.Create('ServerKeyExchange overflow');
end;

function TServerKeyExchange.GetNamedCurve: TCurveName;
begin
  Result := TCurveName(Swap(FNamedCurve));
end;

procedure TServerKeyExchange.SetNamedCurve(Value: TCurveName);
begin
  FNamedCurve := Swap(Ord(Value));
end;

function TServerKeyExchange.GetPublicKey: TBytes;
begin
  SetLength(Result, PublicKeySize);
  Move(PByte(@PublicKeySize)[1], Result[0], PublicKeySize);
end;

procedure TServerKeyExchange.SetPublicKey(const Value: TBytes);
begin
  PublicKeySize := Length(Value);
  Move(Value[0], PByte(@PublicKeySize)[1], Length(Value));
end;

function TServerKeyExchange.GetHashAlgorithm: THashAlgorithm;
begin
  Result := THashAlgorithm(PByte(@PublicKeySize)[1 + PublicKeySize])
end;

procedure TServerKeyExchange.SetHashAlgorithm(Value: THashAlgorithm);
begin
  PByte(@PublicKeySize)[1 + PublicKeySize] := Ord(Value);
end;

function TServerKeyExchange.GetSignatureAndHashAlgorithm: TSignatureAndHashAlgorithm;
begin
  Move(PByte(@PublicKeySize)[1 + PublicKeySize], Result, SizeOf(Result));
end;

function TServerKeyExchange.GetSignatureScheme: TSignatureScheme;
begin
  Result := TSignatureScheme(Swap(PWord(@PByte(@PublicKeySize)[1 + PublicKeySize])^));
end;

procedure TServerKeyExchange.SetSignatureScheme(Value: TSignatureScheme);
begin
  PWord(@PByte(@PublicKeySize)[1 + PublicKeySize])^ := Swap(Ord(Value));
end;

function TServerKeyExchange.GetSignatureSize: Word;
begin
  Result := Swap(PWord(@PByte(@PublicKeySize)[1 + PublicKeySize + SizeOf(TSignatureAndHashAlgorithm)])^);
end;

function TServerKeyExchange.GetSignature: TBytes;
begin
  SetLength(Result, SignatureSize);
  Move(PByte(@PublicKeySize)[1 + PublicKeySize + SizeOf(TSignatureAndHashAlgorithm) + SizeOf(Word)], Result[0], Length(Result));
end;

procedure TServerKeyExchange.SetSignature(const Value: TBytes);
begin
  var L := Length(Value);
  var O := 1 + PublicKeySize + SizeOf(TSignatureAndHashAlgorithm);
  PWord(@PByte(@PublicKeySize)[O])^ := Swap(L);
  Move(Value[0], PByte(@PublicKeySize)[O + SizeOf(Word)],  L);
end;

class function TServerKeyExchange.SizeFor(const Key,
  Signature: TBytes): Integer;
begin
  Result := SizeOf(TServerKeyExchange) + Length(Key) + SizeOf(TSignatureAndHashAlgorithm) + SizeOf(Word) + Length(Signature);
end;

{ TCertificateRequest }

function TCertificateRequest.Payload(Index: Integer): Pointer;
begin
  Result := @PByte(@Self)[Index];
end;

function TCertificateRequest.GetCertificateType(Index: Integer): TClientCertificateType;
begin
  Result := TClientCertificateType(Payload(1 + Index)^);
end;

procedure TCertificateRequest.SetCertificateType(Index: Integer; Value: TClientCertificateType);
begin
  PByte(Payload(1 + Index))^ := Ord(Value);
end;

function TCertificateRequest.GetSignatureAndHashAlgorithmCount: Word;
begin
  Result := Swap(PWord(Payload(1 + CertificateTypesCount))^) div 2;
end;

procedure TCertificateRequest.SetSignatureAndHashAlgorithmCount(Value: Word);
begin
  PWord(Payload(1 + CertificateTypesCount))^ := Swap(2 * Value);
end;

function TCertificateRequest.GetSignatureAndHashAlgorithm(
  Index: Integer): TSignatureAndHashAlgorithm;
begin
  Result := PSignatureAndHashAlgorithm(Payload(1 + CertificateTypesCount + SizeOf(Word) + Index * SizeOf(TSignatureAndHashAlgorithm)))^;
end;

procedure TCertificateRequest.SetSignatureAndHashAlgorithm(Index: Integer;
  const Value: TSignatureAndHashAlgorithm);
begin
  PSignatureAndHashAlgorithm(Payload(1 + CertificateTypesCount + SizeOf(Word) + Index * SizeOf(TSignatureAndHashAlgorithm)))^ := Value;
end;

type
  TOIDSuffix = record
    Name: string;
    Code: Byte;
  end;
const
  OID_SUFFIX: array[0..6] of TOIDSuffix = (
    (Name: 'CN';  Code:  3),
    (Name: 'SN';  Code:  4),
    (Name: 'C';   Code:  6),
    (Name: 'ORG'; Code: 10),
    (Name: 'OU';  Code: 11),
    (Name: 'T';   Code: 12),
    (Name: 'GN';  Code: 42)
  );

function OIDCode(Name: string): Integer;
begin
  for var I := 0 to High(OID_SUFFIX) do
    if OID_SUFFIX[I].Name = Name then
      Exit(OID_SUFFIX[I].Code);
  Result := 0;
end;

function OIDName(Code: Integer): UTF8String;
begin
  for var I := 0 to High(OID_SUFFIX) do
    if OID_SUFFIX[I].Code = Code then
      Exit(UTF8String(OID_SUFFIX[I].Name));
  Result := UTF8String(IntToStr(Code));
end;

function EncodeDN(const DN: string): TBytes;
begin
  SetLength(Result, 4);
  Result[2] := $30;
  var I := Pos('/', DN) + 1;
  var J := Pos('=', DN, I);
  while (I > 1) and (J > I) do
  begin
    var K := Pos('/', DN, J) - 1;
    if K < 0 then
      K := Length(DN);
    var OU := Copy(DN, I, J - I);
    var Tag: Byte;
    if OU[Length(OU)] = ':' then
    begin
      SetLength(OU, Length(OU) - 1);
      Tag := $0C // UTF8
    end else begin
      Tag := $13; // ANSI
    end;
    var OID := OIDCode(OU);
    if OID > 0 then
    begin
      var N := K - J;
      Assert(9 + N < 128);
      var L := Length(Result);
      SetLength(Result, L + 11 + N);
      Result[L +  0] := $31; // SEQUENCE
      Result[L +  1] := 9 + N;
      Result[L +  2] := $30; // SEQUENCE
      Result[L +  3] := 7 + N;
      Result[L +  4] := $06; // OID
      Result[L +  5] := 3;   // 2.5.4.x
      Result[L +  6] := 40 * 2 + 5;
      Result[L +  7] := 4;
      Result[L +  8] := OID;
      Result[L +  9] := Tag;
      Result[L + 10] := N;
      Move(DN[J + 1], Result[L + 11], N);
    end;
    I := K + 2;
    J := Pos('=', DN, I);
  end;
  var L := Length(Result) - 4;
  if L >= 128 then
  begin
    Assert(L < $FFFF);
    if L <= 255 then
    begin
      Insert([L], Result, 4);
      L := $81;
    end else begin
      Insert([L shr 8, L and 255], Result, 4);
      L := $82;
    end;
  end;
  Result[3] := L;
  var W: Word := Swap(Length(Result) - 2);
  Move(W, Result[0], 2);
end;

function DecodeDN(var Ptr: PByte; var Len: Integer): UTF8String;
begin
  Result := '';
  var L := Swap(PWord(Ptr)^);
  if L > Len then
    RaiseOverFlow('DistinguishedName');
  if Ptr[2] <> $30 then
    RaiseDecodeError('DistinguishedName');
  var N: Integer := Ptr[3];
  var I := 4;
  if N > 128 then
  begin
    if N = $81 then
    begin
      N := Ptr[4];
      Inc(I);
    end else
    if N = $82 then
    begin
      N := Ptr[4] shl 8 + Ptr[5];
      Inc(I, 2);
    end else
      RaiseOverFlow('DistinguishedName');
  end;
  if N <> L - I + 2 then
    RaiseDecodeError('DistinguishedName');
  while N > 0 do
  begin
    var X := Ptr[I + 1];
    if X + 2 > N then
      RaiseOverFlow('DistinguishedName');
    Dec(N, X + 2);

    if (Ptr[I + 0] <> $31)
    // 1 = X
    or (Ptr[I + 2] <> $30)
    or (Ptr[I + 3] <> X - 2)
    or (Ptr[I + 4] <> $06)
    or (Ptr[I + 5] <> 3)
    or (Ptr[I + 6] <> 40 * 2 + 5)
    or (Ptr[I + 7] <> 4)
    // 8 = OID
    or (not (Ptr[I + 9] in [$0C, $13]))
    or (Ptr[I + 10] <> X - 9)
    then
      RaiseDecodeError('DistinguishedName');

    var O := OIDName(Ptr[I + 8]);
    if Ptr[I + 9] = $0C then
      O := O + ':';
    var S: UTF8String;
    SetLength(S, X - 9);
    Move(Ptr[I + 11], S[1], Length(S));
    Result := Result + '/' + O + '=' + S;

    Inc(I, X + 2);
  end;
  Inc(L, 2);
  Inc(Ptr, L);
  Dec(Len, L);
end;

function TCertificateRequest.GetDistinguishedNames: TArray<UTF8String>;
begin
  var Ofs := 1 + CertificateTypesCount + SizeOf(Word) + SignatureAndHashAlgorithmCount * SizeOf(TSignatureAndHashAlgorithm);
  var Len: Integer := Swap(PWord(Payload(Ofs))^);
  Inc(Ofs, 2);
  var Ptr: PByte := Payload(Ofs);
  while Len > 0 do
  begin
    var L := Length(Result);
    SetLength(Result, L + 1);
    Result[L] := DecodeDN(Ptr, Len);
  end;
end;

procedure TCertificateRequest.SetCertificateTypes(const Values: TArray<TClientCertificateType>);
begin
  CertificateTypesCount := Length(Values);
  Move(Values[0], Payload(1)^, Length(Values));
end;

function TCertificateRequest.GetCertificateTypes: TArray<TClientCertificateType>;
begin
  SetLength(Result, CertificateTypesCount);
  Move(Payload(1)^, Result[0], CertificateTypesCount);
end;

procedure TCertificateRequest.SetSignatureSchemes(const Values: TArray<TSignatureScheme>);
begin
  SignatureAndHashAlgorithmCount := Length(Values);
  var P: PWord := Payload(1 + CertificateTypesCount + 2);
  for var I := 0 to Length(Values) - 1 do
  begin
    P[I] := Swap(Ord(Values[I]));
  end;
end;

function TCertificateRequest.GetSignatureSchemes: TArray<TSignatureScheme>;
begin
  SetLength(Result, SignatureAndHashAlgorithmCount);
  var P: PWord := Payload(1 + CertificateTypesCount + 2);
  for var I := 0 to Length(Result) - 1 do
  begin
    Result[I] := TSignatureScheme(Swap(P[I]));
  end;
end;

class function TCertificateRequest.SizeFor(
  const CertificateTypes: TArray<TClientCertificateType>;
  const SignatureSchemes: TArray<TSignatureScheme>;
  const EncodedDistinguishedNames: TBytes): Integer;
begin
  Result := 1 + Length(CertificateTypes)
          + 2 + 2 * Length(SignatureSchemes)
          + 2 + Length(EncodedDistinguishedNames);
end;

class function TCertificateRequest.EncodeDistinguishedNames(
  const Values: TArray<UTF8String>): TBytes;
begin
  Result := nil;
  for var I := 0 to Length(Values) - 1 do
  begin
    Result := Result + EncodeDN(string(Values[I]));
  end;
end;

procedure TCertificateRequest.SetEncodedDistinguishedNames(const Values: TBytes);
begin
  var Len := Length(Values);
  var Ofs := 1 + CertificateTypesCount + SizeOf(Word) + SignatureAndHashAlgorithmCount * SizeOf(TSignatureAndHashAlgorithm);
  PWord(Payload(Ofs))^ := Swap(Len);
  if Len > 0 then
    Move(Values[0], Payload(Ofs + 2)^, Len);
end;

{ TClientHello }

function TClientHello.CipherList: PCipherList;
begin
  Result := @PByte(@Self)[SizeOf(Self) + SessionIDLen];
end;

function TClientHello.CompressionList: PCompressionList;
begin
  Result := @PByte(@Self)[SizeOf(Self) + SessionIDLen + 2 + CipherList.Size];
end;

function TClientHello.ExtensionList: PExtensionList;
begin
  Result := @PByte(@Self)[SizeOf(Self) + SessionIDLen + 2 + CipherList.Size + 1 + CompressionList.Count];
end;

function TClientHello.HasExtensions(HandshakeSize: Cardinal): Boolean;
begin
  Result := HandshakeSize > SizeOf(Self) + SessionIDLen + 2 + CipherList.Size + 1 + CompressionList.Count;
end;

function TClientHello.GetSessionID: TBytes;
begin
  SetLength(Result, SessionIDLen);
  if SessionIDLen > 0 then
    Move(PByte(@Self)[SizeOf(Self)], Result[0], SessionIDLen);
end;

procedure TClientHello.SetSessionID(const Value: TBytes);
begin
  SessionIDLen := Length(Value);
  if SessionIDLen > 0 then
    Move(Value[0],  PByte(@Self)[SizeOf(Self)], SessionIDLen);
end;

end.

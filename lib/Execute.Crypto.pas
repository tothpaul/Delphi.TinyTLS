unit Execute.Crypto;

{
   Delphi Tiny TLS 1.2 implementation (c)2025 Execute SARL

   https://github.com/tothpaul

}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Hash,
  System.IOUtils,
  Velthuis.BigIntegers;

type
  TRSAPublicKey = record
    modulus         : TBytes;  // n
    publicExponent  : Integer; // e
    procedure LoadKey(Data: PByte; Size: Integer);
    function KeyLength: Integer;
    procedure Crypt(const Data: array of byte; Target: PByte);
    function DeCrypt(Data: PByte; Len: Integer): TBytes;
  end;

  TRSAPrivateKey = record
    modulus         : TBytes;  // n
    privateExponent : TBytes;  // d
    prime1          : TBytes;  // p
    prime2          : TBytes;  // q
    exponent1       : TBytes;  // d mod (p - 1)
    exponent2       : TBytes;  // d mod (q - 1)
    coefficient     : TBytes;  // (inverse of q) mod p
    procedure LoadKey(Data: PByte; Size: Integer);
    function KeyLength: Integer;
    function Encrypt(Data: TBytes): TBytes;
    function Encrypt2(Data: TBytes): TBytes;
    function Decrypt(Data: PByte; Len: Integer): TBytes;
  end;

function PKCS1Pad(const Data: array of byte; KeyLen: Integer; APrivate: Boolean): TBytes;

implementation

uses
  Execute.TLS.Debug,
  Execute.Winapi.BCrypt;


{ TRSAPublicKey }

function GetKeyLength(const Modulus: TBytes): Integer;
begin
  Result := Length(Modulus);
  if (Result > 0) and (Modulus[0] = 0) then
    Dec(Result);
end;

function PKCS1Pad(const Data: array of byte; KeyLen: Integer; APrivate: Boolean): TBytes;
var
  Len: Integer;
begin
  len := KeyLen - Length(Data);

  if Len < 11 then
    raise Exception.Create('RSA Message too long');

  SetLength(Result, KeyLen);
  Result[0] := 0;
  if APrivate then
  begin
    Result[1] := 1;
    FillChar(Result[2], Len - 3, 255);
  end else begin
    Result[1] := 2;
    FillRandom(Result[2], Len - 3);
    for var I := 2 to Len - 1 do
      if Result[I] = 0 then
        Result[I] := I or 1;
    Result[Len - 1] := 0;
  end;
  Move(Data[0], Result[len], Length(Data));
end;

function PKCS1Trim(var AData: TBytes): Boolean;
var
  Len: Integer;
  TB : Byte;
  Pad: Integer;
begin
  Result := False;
  Len := Length(AData);
  if (Len < 11) or (AData[0] <> 0) then
    Exit;
  TB := AData[1];
  if TB > 2 then
    Exit;
  if TB = 0 then
  begin
    Pad := 1;
    while (Pad < Len) and (AData[Pad + 1] = 0) do
      Inc(Pad);
  end else begin
    Pad := 2;
    while (Pad < Len) and (AData[Pad] <> 0) do
    begin
      if (TB = 1) and (AData[Pad] <> 255) then
        Exit;
      Inc(Pad);
    end;
  end;
  if (Pad < 10) or (Pad = Len)  then
    Exit;
  Delete(AData, 0, Pad + 1);
  Result := True;
end;

procedure Init(var i: BigInteger; Bytes: PByte; Len: Integer);
var
  Index: Integer;
begin
  i := Bytes^;
  for Index := 1 to Len - 1 do
  begin
    Inc(Bytes);
    i := i * 256 + Bytes^;
  end;
end;

function Quotient(var i: BigInteger; m: Cardinal): Cardinal;
begin
  if Length(i.Magnitude) = 0 then
    Result := 0
  else begin
    Result := i.Magnitude[0] mod m;
    i := i div m;
  end;
end;

procedure RSACrypt(Data: PByte; Count: Integer; const Modulus: TBytes; var e: BigInteger; KeyLen: Integer; Target: PByte);
var
  p, m, c: BigInteger;
begin
  Init(p, Data, Count);
  Init(m, PByte(Modulus), Length(Modulus));
  c := BigInteger.ModPow(p, e, m);
  for var I := KeyLen - 1 downto 0 do  // reverse order ?
  begin
    Target[I] := Quotient(c, 256);
  end;
end;

procedure TRSAPublicKey.Crypt(const Data: array of Byte; Target: PByte);
begin
  var Bytes := PKCS1Pad(Data, KeyLength, False);
  DebugSession.DumpConst('PCKS1Pad', Bytes, Length(Bytes));
  var e: BigInteger := publicExponent;
  RSACrypt(PByte(Bytes), Length(Bytes), Modulus, e, KeyLength, Target);
end;

function TRSAPublicKey.DeCrypt(Data: PByte; Len: Integer): TBytes;
begin
  var e: BigInteger := publicExponent;
  SetLength(Result, KeyLength);
  RSACrypt(Data, Len, Modulus, e, KeyLength, PByte(Result));
  PKCS1Trim(Result);
end;

function TRSAPublicKey.KeyLength: Integer;
begin
  Result := GetKeyLength(modulus);
end;

type
  TDERReader = record
    Ptr: PByte;
    Len: Integer;
    procedure Init(APtr: Pointer; ALen: Integer);
    function NextByte: Byte;
    function Skip(Code: Byte): Boolean;
    function GetLen: Integer;
    procedure OpenSequence();
    function GetBytes: TBytes;
    function GetInteger: Integer;
  end;

procedure TDERReader.Init(APtr: Pointer; ALen: Integer);
begin
  Ptr := APtr;
  Len := ALen;
end;

function TDERReader.NextByte: Byte;
begin
  if Len = 0 then
    raise Exception.Create('Unexpected DER end');
  Result := Ptr^;
  Inc(Ptr);
  Dec(Len);
end;

function TDERReader.GetBytes: TBytes;
begin
  if not Skip($02) then
    raise Exception.Create('Expected INTEGER');
  var Size := GetLen;
  if Ptr^ = 0 then
  begin
    Dec(Size);
    Inc(Ptr);
    Dec(Len);
  end;
  SetLength(Result, Size);
  Move(Ptr^, Result[0], Size);
  Inc(Ptr, Size);
  Dec(Len, Size);
end;

function TDERReader.GetInteger: Integer;
begin
  if not Skip($02) then
    raise Exception.Create('Expected INTEGER');
  var Size := GetLen;
  if Size > 4 then
    raise Exception.Create('INTEGER overflow');
  Result := 0;
  Move(Ptr^, Result, Size);
  Inc(Ptr, Size);
  Dec(Len, Size);
end;

function TDERReader.Skip(Code: Byte): Boolean;
begin
  Result := (Len > 0) and (Ptr^ = Code);
  if Result then
  begin
    Inc(Ptr);
    Dec(Len);
  end;
end;

function TDERReader.GetLen: Integer;
begin
  Result := NextByte;
  if Result > 128 then
  begin
    var Count := Result and $7F;
    Result := 0;
    for var Index := 1 to Count do
    begin
      Result := Result shl 8 + NextByte;
    end;
  end;
end;

procedure TDERReader.OpenSequence;
begin
  if not Skip($30) then
    raise Exception.Create('DER Sequence not found');
  Len := GetLen;
end;

procedure TRSAPublicKey.LoadKey(Data: PByte; Size: Integer);
begin
  var DER: TDERReader;
  DER.Init(Data, Size);
  DER.OpenSequence();
  Modulus := DER.GetBytes;          // n
  PublicExponent := DER.GetInteger; // e
  if DER.Len > 0 then
    raise Exception.Create('DER extra data');
end;

procedure TRSAPrivateKey.LoadKey(Data: PByte; Size: Integer);
begin
  var DER: TDERReader;
  DER.Init(Data, Size);
  DER.OpenSequence();
  var i := DER.GetInteger;         // 0
  Assert(i = 0);
  Modulus := DER.GetBytes;         // n
  Assert(Length(Modulus) = 256);
  i := DER.GetInteger; // 65537    // e
  Assert(i = 65537);
  PrivateExponent := DER.GetBytes; // d
  Assert(Length(PrivateExponent) = 256);
  prime1 := DER.GetBytes;
  prime2 := DER.GetBytes;
  exponent1 := DER.GetBytes;
  exponent2 := DER.GetBytes;
  coefficient := DER.GetBytes;
end;

function TRSAPrivateKey.KeyLength: Integer;
begin
  Result := GetKeyLength(modulus);
end;

function TRSAPrivateKey.Encrypt(Data: TBytes): TBytes;
begin
  var Bytes := PKCS1Pad(Data, KeyLength, True);
  var e: BigInteger;
  Init(e, PByte(privateExponent), Length(privateExponent));
  SetLength(Result, KeyLength);
  RSACrypt(PByte(Bytes), Length(Bytes), Modulus, e, KeyLength, PByte(Result));
end;

function TRSAPrivateKey.Encrypt2(Data: TBytes): TBytes;
begin
{
    modulus         : TBytes;  // n
    privateExponent : TBytes;  // d
    prime1          : TBytes;  // p
    prime2          : TBytes;  // q
    exponent1       : TBytes;  // d mod (p - 1)
    exponent2       : TBytes;  // d mod (q - 1)
    coefficient     : TBytes;  // (inverse of q) mod p

}
  var Bytes := PKCS1Pad(Data, KeyLength, True);

  var p, q, dp, dq, qInv: BigInteger;
  Init(p, PByte(prime1), Length(prime1));
  Init(q, PByte(prime2), Length(prime2));
  Init(dp, PByte(exponent1), Length(exponent1));
  Init(dq, PByte(exponent2), Length(exponent2));
  Init(qInv, PByte(coefficient), Length(coefficient));

  var c: BigInteger;
  Init(c, PByte(Bytes), Length(Bytes));

  var m1 := BigInteger.ModPow(c, dp, p);
  var m2 := BigInteger.ModPow(c, dq, q);

  var h := (qInv * (m1 - m2)) mod p;
  var m := m2 + h * q;

  SetLength(Result, KeyLength);
  for var I := KeyLength - 1 downto 0 do  // reverse order ?
  begin
    Result[I] := Quotient(m, 256);
  end;
end;

function TRSAPrivateKey.DeCrypt(Data: PByte; Len: Integer): TBytes;
begin
  var e: BigInteger;
  Init(e, @privateExponent[0], Length(privateExponent));
  SetLength(Result, KeyLength);
  RSACrypt(Data, Len, Modulus, e, KeyLength, PByte(Result));
  PKCS1Trim(Result);
end;

end.

program TLSDemo;

uses
  Vcl.Forms,
  TLSDemo.Main in 'TLSDemo.Main.pas' {Main},
  Execute.HTTPClient in '..\lib\Execute.HTTPClient.pas',
  Execute.Sockets in '..\lib\Execute.Sockets.pas',
  Execute.TinyTLS in '..\lib\Execute.TinyTLS.pas',
  Execute.TinyTLS.Win.Ciphers in '..\lib\Execute.TinyTLS.Win.Ciphers.pas',
  Execute.Winapi.BCrypt in '..\lib\Execute.Winapi.BCrypt.pas',
  Execute.TinyTLS.Fragments in '..\lib\Execute.TinyTLS.Fragments.pas',
  Execute.TinyTLS.Extensions in '..\lib\Execute.TinyTLS.Extensions.pas',
  Execute.TLS.Debug in '..\lib\Execute.TLS.Debug.pas',
  Execute.TLS.Debug.Values in '..\lib\Execute.TLS.Debug.Values.pas',
  Execute.Crypto in '..\lib\Execute.Crypto.pas',
  Execute.TinyTLS.Types in '..\lib\Execute.TinyTLS.Types.pas',
  Execute.SChannel in '..\lib\Execute.SChannel.pas',
  Execute.WinSSPI in '..\lib\Execute.WinSSPI.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMain, Main);
  Application.Run;
end.

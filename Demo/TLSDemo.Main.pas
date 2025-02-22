unit TLSDemo.Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls;

type
  TMain = class(TForm)
    btGO: TButton;
    mmHtml: TMemo;
    edURL: TComboBox;
    procedure btGOClick(Sender: TObject);
  private
    { Déclarations privées }
  public
    { Déclarations publiques }
  end;

var
  Main: TMain;

implementation

{$R *.dfm}

uses
  Execute.HTTPClient;

procedure TMain.btGOClick(Sender: TObject);
begin
  mmHtml.Text := wget(edURL.Text);
end;

end.

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
    cbEgine: TComboBox;
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
  Execute.HTTPClient,
  System.DateUtils;


procedure TMain.btGOClick(Sender: TObject);
begin
  mmHtml.Text := 'Loading...';
  try
    THTTPClient.DefaultTLSEngine := TTLSEngine(cbEgine.ItemIndex);
    mmHtml.Lines.LineBreak := #10;
    mmHtml.Lines.Text := wget(edURL.Text);
  except
    on e: Exception do
      mmHtml.Text := e.ClassName + ':'  + e.Message;
  end;
end;

end.

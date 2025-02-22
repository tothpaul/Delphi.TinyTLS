object Main: TMain
  Left = 0
  Top = 0
  Caption = 'TLS Demo'
  ClientHeight = 441
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  DesignSize = (
    624
    441)
  TextHeight = 15
  object btGO: TButton
    Left = 541
    Top = 6
    Width = 75
    Height = 25
    Anchors = [akTop, akRight]
    Caption = 'GO'
    TabOrder = 0
    OnClick = btGOClick
  end
  object mmHtml: TMemo
    Left = 0
    Top = 37
    Width = 616
    Height = 396
    Anchors = [akLeft, akTop, akRight, akBottom]
    Lines.Strings = (
      'TLS 1.2 demonstration'
      ''
      'support ONLY TLS 1.2 with few Ciphers'
      ''
      'made to study TLS protocol, use at your own risk :D')
    ScrollBars = ssBoth
    TabOrder = 1
    WordWrap = False
  end
  object edURL: TComboBox
    Left = 0
    Top = 8
    Width = 535
    Height = 23
    Anchors = [akLeft, akTop, akRight]
    ItemIndex = 0
    TabOrder = 2
    Text = 'https://www.howsmyssl.com/'
    Items.Strings = (
      'https://www.howsmyssl.com/'
      'http://www.google.fr'
      'https://www.google.fr'
      'https://www.embarcadero.com'
      'https://tls12.browserleaks.com/'
      'https://tls13.browserleaks.com/')
  end
end

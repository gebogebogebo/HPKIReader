using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using gebo.NFC;

namespace gebo.HPKIReaderLib
{
    public partial class HPKIReader : gebo.NFC.ICReader
    {
        // 標準仕様に基づいてカードオブジェクト情報を取得する
        // 仕様＝JIS X 6320 , ISO/IEC 7816-15 , PKCS#15
        public static void GetCardObjectsJISX6320()
        {
            try {
                var aplist = new List<byte[]>();
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // get AP
                    {
                        // SELECTコマンドで`E8 28 BD 08 0F`をパーシャル指定したDFを指定
                        for (bool isFirst=true; ; ) {
                            byte[] apdu = null;
                            if(isFirst) {
                                // 最初のDFをGETするAPDU
                                apdu = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x05, 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x00 };
                            } else {
                                // 次のDFをGETするAPDU
                                apdu = new byte[] { 0x00, 0xA4, 0x04, 0x02, 0x05, 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x00 };
                            }
                            var response = reader.SendandResponse(apdu);
                            if (!response.IsSuccess) {
                                break;
                            }
                            isFirst = false;
                            var ap = getAPfromFCI(response.Data);
                            if( ap != null) {
                                aplist.Add(ap);
                            }
                        }
                    }

                    // all AP
                    foreach( var ap in aplist) {
                        // SELECT AP
                        var apdu = new List<byte>();
                        {
                            apdu.AddRange(new List<byte> { 0x00, 0xA4, 0x04, 0x00 });
                            apdu.Add((byte)ap.Length);
                            apdu.AddRange(ap);
                            apdu.Add(0x00);
                        }
                        if (reader.SendandResponse(apdu.ToArray()).IsSuccess == false)
                            continue;

                        // Read EF.OD
                        var response = reader.SendandResponse(new byte[] {0x00,0xB0,0x91,0x00,0x00});
                        if (!response.IsSuccess)
                            continue;

                        // log Response Format DER(ASN.1)
                        {
                            var data = gebo.NFC.Common.BytesToHexString(response.Data);
                            logger.Debug("Read EF.OD");
                            logger.Debug($"AP={gebo.NFC.Common.BytesToHexString(ap)}");
                            logger.Debug($"Response Format DER(ASN.1)={data}");
                        }

                        var parsedEF0D = parseEF0D(response.Data);

                        foreach(var rec in parsedEF0D) {
                            byte[] efid = Common.HexStringToBytes(rec.Value);
                            readEFrec(reader,efid);
                        }
                    }
                }


            } catch(Exception ex) {
                logger.Error(ex);
            }
        }

        // FCIパース(AP識別子をGETする)
        private static byte[] getAPfromFCI(byte[] fci)
        {
            try {
                // Format BER-TLV
                // 3byte目が84(DF)のときだけ処理
                if (fci[2] == 0x84) {
                    int size = fci[3];
                    var ap = fci.ToArray().Skip(4).Take(size).ToArray();
                    return (ap);
                }
            } catch (Exception) {

            }
            return null;
        }

        // EF.0Dパース
        private static Dictionary<byte, string> parseEF0D(byte[] ef0d)
        {
            // ほんとはef0dをパースする必要がある が、
            // https://holtstrom.com/michael/tools/asn1decoder.php
            // で出た結果をはりつけてしまう。

            var tblCIOChoice = new Dictionary<byte, string>();
            tblCIOChoice.Add(0, "0002");
            tblCIOChoice.Add(1, "0003");
            tblCIOChoice.Add(4, "0004");
            tblCIOChoice.Add(7, "0005");
            tblCIOChoice.Add(8, "0001");

            /* memo
            // check https://holtstrom.com/michael/tools/asn1decoder.php

            // AP1(署名)もAP2(認証)も同じ
            [0] { PrivateKeys
               SEQUENCE {
                  OCTETSTRING 0002
               }
            }
            [1] { PublicKeys
               SEQUENCE {
                  OCTETSTRING 0003
               }
            }
            [4] { Certificates
               SEQUENCE {
                  OCTETSTRING 0004
               }
            }
            [7] { DataContainerObjects
               SEQUENCE {
                  OCTETSTRING 0005
               }
            }
            [8] { AuthObjects
               SEQUENCE {
                  OCTETSTRING 0001
               }
            }
            */

            return (tblCIOChoice);
        }

        private static void readEFrec(ICReader reader,byte[] efid)
        {
            // SELECT
            var apdu = new List<byte>();
            {
                apdu.AddRange(new List<byte> { 0x00, 0xA4, 0x02, 0x0C });
                apdu.Add((byte)efid.Length);
                apdu.AddRange(efid);
            }

            if (reader.SendandResponse(apdu.ToArray()).IsSuccess == false) {
                // Error
                return;
            }

            var der = gebo.NFC.Der.ReadDER(reader);
        }
    }

}

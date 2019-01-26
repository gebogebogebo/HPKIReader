using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gebo.NFC
{
    public class Cert
    {
        protected static NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        public static byte[] readCert(ICReader reader)
        {
            var certDER = new List<byte>();

            // READ BINARY
            int datasize = 0;
            {
                // http://www.geocities.co.jp/SiliconValley-SanJose/3377/asn1Body.html
                // ブロックの最初の4byteを読む
                // ⇒30:82:06:2B
                // 30 = タグ
                //  ‭0011-0000
                //  00          b8-b7:クラス        00   = 汎用
                //    1         b6   :構造化フラグ  1    = 構造型
                //     1-0000   b5-b1:タグ番号      0x10 = SEQUENCE(ASN.1 オブジェクトの集合を表記するための型)

                // 82 = 値の長さ1(レングス)
                //  ‭1000-0010
                //‬  1           b8   :              1    = 128オクテット(byte)以上
                //   000-0010   b7-b1:              0x02 = 長さ部の長さ = 2byte
                //                                          ※この後2byteが値の部分の長さという意味

                // 06:2B = 値の長さ2(レングス)
                //  dec = 1579                      値の長さは1579byte
                // ※DERデータが1579byte、という意味（この4byteは含まれない）

                var response = reader.SendandResponse(new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x04 });
                if (response.IsSuccess == false) {
                    throw (new Exception("READ BINARY Error"));
                }

                // blockData-4byte + status-2byte 
                datasize = ChangeEndian.Reverse(BitConverter.ToUInt16(response.Data, 2));

                // add header-4byte
                datasize = datasize + 4;
            }

            // get block num
            int blocksize = 256;            // 決めうち！
            int blocknum = (int)Math.Ceiling(datasize / (double)blocksize);
            {
                var apdu = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
                for (int intIc = 0; intIc < blocknum; intIc++) {
                    apdu[2] = (byte)intIc;
                    var response = reader.SendandResponse(apdu);
                    if (response.IsSuccess == false) {
                        throw (new Exception("READ BINARY Error"));
                    }
                    // blockdata(256byte)
                    certDER.AddRange(response.Data.ToList());
                }
            }
            certDER = certDER.Take(datasize).ToList();

            // log
            logCert(certDER.ToArray());

            return (certDER.ToArray());
        }

        private static void logCert(byte[] certDER)
        {
            logger.Debug("X.509-Parse-log");
            try {
                var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certDER);
                //logger.Debug("X.509v3証明書の発行先であるプリンシパルの名前（古い形式）");
                //logger.Debug(x509.GetName());

                logger.Debug("X.509v3証明書を発行した証明機関の名前");
                logger.Debug(x509.Issuer);

                logger.Debug("X.509v3証明書のサブジェクトの識別名");
                logger.Debug(x509.Subject);

                logger.Debug("X.509v3証明書のハッシュ値の16進文字列");
                logger.Debug(x509.GetCertHashString());

                logger.Debug("X.509v3証明書の発効日");
                logger.Debug(x509.GetEffectiveDateString());

                logger.Debug("X.509v3証明書の失効日");
                logger.Debug(x509.GetExpirationDateString());

                //logger.Debug("X.509v3証明書を発行した証明機関の名前(古い形式)");
                //logger.Debug(x509.GetIssuerName());

                logger.Debug("X.509v3証明書のキーアルゴリズム情報");
                logger.Debug(x509.GetKeyAlgorithm());

                logger.Debug("X.509v3証明書のキーアルゴリズムパラメータ");
                logger.Debug(x509.GetKeyAlgorithmParametersString());

                logger.Debug("X.509v3証明書の公開鍵");
                logger.Debug(x509.GetPublicKeyString());

                logger.Debug("X.509v3証明書のシリアル番号");
                logger.Debug(x509.GetSerialNumberString());

                logger.Debug("X.509v3証明書の形式の名前");
                logger.Debug(x509.GetFormat());

                //logger.Debug("X.509証明書全体の生データ");
                //logger.Debug(x509.GetRawCertDataString());

            } catch (Exception ex) {
                logger.Debug(ex);
            }
        }

        public static byte[] GetPublicKey(byte[] certDER)
        {
            byte[] publickeyDER = null;

            try {
                // DERで取得
                List<byte> pubkey_pkcs8 = new List<byte>();
                {
                    var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certDER);

                    // ここで取れるデータはPKCS#1形式の公開鍵
                    // 先頭に
                    // 30820122300d06092a864886f70d01010105000382010f00
                    // を付加するとOpenSSLで取り扱い可能なPKCS#8になる
                    // https://qiita.com/hotpepsi/items/128f3a660cee8b5467c6
                    byte[] pubkey_pkcs1 = x509.GetPublicKey();

                    pubkey_pkcs8.AddRange(Common.HexStringToBytes("30820122300d06092a864886f70d01010105000382010f00").ToArray());
                    pubkey_pkcs8.AddRange(pubkey_pkcs1.ToArray());
                }

                publickeyDER = pubkey_pkcs8.ToArray();

            } catch (Exception ex) {
                logger.Debug(ex);
            }

            return publickeyDER;
        }


    }
}

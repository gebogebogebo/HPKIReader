using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gebo.NFC
{
    public class Der
    {
        protected static NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        public static byte[] ReadDER(ICReader reader)
        {
            var derData = new List<byte>();

            try {

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

                    if( response.Data.Length > 0 && response.Data[0] == 0xff) {
                        throw (new Exception("READ BINARY No Data"));
                    }

                    // check Length field
                    if (gebo.NFC.Common.GetBit(response.Data[1], 7)) {
                        // over 128 byte 

                        // blockData-4byte + status-2byte 
                        datasize = ChangeEndian.Reverse(BitConverter.ToUInt16(response.Data, 2));

                        // add header-4byte
                        datasize = datasize + 4;
                    } else {
                        datasize = response.Data[1];

                        // add header-2byte
                        datasize = datasize + 2;
                    }
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
                        derData.AddRange(response.Data.ToList());
                    }
                }
                derData = derData.Take(datasize).ToList();

                // log
                {
                    logger.Debug("Read DER - parse at https://holtstrom.com/michael/tools/asn1decoder.php");
                    logger.Debug($"DER(ASN.1)={gebo.NFC.Common.BytesToHexString(derData.ToArray())}");
                }

            } catch (Exception ex) {
                logger.Debug(ex);
            }

            return (derData.ToArray());
        }


    }
}

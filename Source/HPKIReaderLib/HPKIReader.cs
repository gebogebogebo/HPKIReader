using System;
using System.Collections.Generic;
using System.Linq;
using gebo.NFC;

namespace gebo.HPKIReaderLib
{
    public partial class HPKIReader : ICReader
    {
        // パーシャルDF(E8:28:BD:08:0F)
        private static readonly string PARTIAL_DF = "E828BD080F";

        // AP1:署名に使用するDF識別子
        private static readonly string ID_SIG_AP = PARTIAL_DF + "A000000391000000000001";
        private static readonly string ID_SIG_CERT = "0016";
        private static readonly string ID_SIG_PIN = "0002";
        private static readonly string ID_SIG_KEY = "000C";

        // AP2:認証に使用するDF識別子
        private static readonly string ID_AUTH_AP = PARTIAL_DF + "A000000391000000000002";
        private static readonly string ID_AUTH_CERT = "0016";
        private static readonly string ID_AUTH_PIN = "0002";
        private static readonly string ID_AUTH_KEY = "000C";

        // APDU
        private static readonly string APDU_SELECT_SIG_AP = "00A4040010" + ID_SIG_AP + "00";
        private static readonly string APDU_SELECT_SIG_CERT = "00A4020C02" + ID_SIG_CERT;
        private static readonly string APDU_SELECT_SIG_PIN = "00A4020C02" + ID_SIG_PIN;
        private static readonly string APDU_SELECT_SIG_KEY = "00A4020C02" + ID_SIG_KEY;
        private static readonly string APDU_SELECT_AUTH_AP = "00A4040010" + ID_AUTH_AP + "00";
        private static readonly string APDU_SELECT_AUTH_CERT = "00A4020C02" + ID_AUTH_CERT;
        private static readonly string APDU_SELECT_AUTH_PIN =  "00A4020C02" + ID_AUTH_PIN;
        private static readonly string APDU_SELECT_AUTH_KEY = "00A4020C02" + ID_AUTH_KEY;

        private static byte[] getEF(string apduSelectAP,string apduSelectMF)
        {
            logger.Debug("getEF");
            byte[] certDER = null;

            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectAP)).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // select MF
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectMF)).IsSuccess == false) {
                        throw (new Exception("SELECT MF Error"));
                    }

                    // READ Cert
                    certDER = gebo.NFC.Cert.readCert(reader);
                }

            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (certDER);
        }

        private static int getPINRetryCount(string apduSelectAP,string apduSelectMF)
        {
            logger.Debug("<<<getPINRetryCount>>>");
            int retrycount = -1;

            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectAP)).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // SELECT MF
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectMF)).IsSuccess == false)
                        throw (new Exception("SELECT MF Error"));

                    // VERIFY
                    // P2=0x88を指定しているが、これは以下SEQの0088を指定する
                    // 18-001_JAHIS HPKI対応ICカードガイドラインVer.3.0
                    // P61. B.4.4 pwdReference
                    /*
                    SEQUENCE {
                       SEQUENCE {
                          UTF8String 'PIN'
                          BITSTRING 1000000 : 6 unused bit(s)
                       }
                       SEQUENCE {
                          OCTETSTRING 08
                       }
                       [1] {
                          BITSTRING 11001000 : 3 unused bit(s)
                          [0A] 02
                          INTEGER 0x04 (4 decimal)
                          INTEGER 0x00 (0 decimal)
                          INTEGER 0x10 (16 decimal)
                          [0] 0088
                       }
                    }
                    */

                    var res = reader.SendandResponse(new byte[] { 0x00, 0x20, 0x00, 0x88 });
                    if (res.Sw1 == 0x63) {
                        retrycount = res.Sw2 & 0xF;
                    }
                }
            } catch (Exception ex) {
                logger.Error(ex);
                return (-9);
            }
            return (retrycount);
        }

        private static byte[] signature(string pin, byte[] digestSHA1, string apduSelectAP, string apduSelectPIN, string apduSelectKey,bool enableDigestInfo)
        {
            byte[] signature = null;

            try {
                if (pin.Length <= 0) {
                    throw new Exception("Error PIN_REQUIRED");
                }

                logger.Debug("DIGEST SHA1 ---");
                logger.Debug(Common.BytesToHexString(digestSHA1));
                logger.Debug("--- DIGEST SHA1");

                byte[] digestInfo;
                if (enableDigestInfo) {
                    digestInfo = createDigestInfo(digestSHA1);
                } else {
                    digestInfo = digestSHA1;
                }

                logger.Debug("DIGESTINFO ---");
                logger.Debug(Common.BytesToHexString(digestInfo));
                logger.Debug("--- DIGESTINFO");

                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectAP)).IsSuccess == false)
                        throw (new Exception("SELECT AP Error"));

                    // SELECT PIN IDF
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectPIN)).IsSuccess == false)
                        throw (new Exception("SELECT PIN IDF Error"));


                    // VERIFY PIN
                    {
                        byte[] pinbyte = System.Text.Encoding.ASCII.GetBytes(pin);

                        var apdu = new List<byte>();
                        apdu.AddRange(new List<byte> { 0x00, 0x20, 0x00, 0x88 });
                        apdu.Add((byte)pinbyte.Length);
                        apdu.AddRange(pinbyte.ToList());

                        // send
                        if (reader.SendandResponse(apdu.ToArray()).IsSuccess == false)
                            throw (new Exception("VERIFY PIN Error"));
                    }

                    // SELECT 秘密鍵IEF
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(apduSelectKey)).IsSuccess == false)
                        throw (new Exception("SELECT MF Error"));

                    // COMPUTE DIGITAL SIGNATURE
                    // < 80 2A 00 80 [DigestInfo]
                    // > [SIGNATURE]
                    {
                        var apdu = new List<byte>();
                        apdu.AddRange(new List<byte> { 0x80, 0x2A, 0x00, 0x80 });
                        apdu.Add((byte)digestInfo.Length);
                        apdu.AddRange(digestInfo.ToList());
                        apdu.Add((byte)0x00);

                        var res = reader.SendandResponse(apdu.ToArray());
                        if (res.IsSuccess == false) {
                            throw (new Exception("SIGNATURE Error"));
                        }
                        signature = res.Data;
                    }
                }

            } catch (Exception ex) {
                logger.Debug(ex);
            }
            return (signature);
        }

        private static byte[] sigUsingPrivateKey(string pin, string targetFile, string apduSelectAP, string apduSelectPIN, string apduSelectKey)
        {
            byte[] digestSHA1 = null;
            using (var fs = new System.IO.FileStream(targetFile, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
                digestSHA1 = System.Security.Cryptography.SHA1.Create().ComputeHash(fs);
            }
            return (signature(pin, digestSHA1, apduSelectAP, apduSelectPIN, apduSelectKey,true));
        }

        public static byte[] GetCardUID()
        {
            logger.Debug("<<<GetCardUID>>>");
            byte[] uid = null;
            try {

                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // get UID
                    var response = reader.SendandResponse(new byte[] { 0xFF, 0xCA, 0x00, 0x00, 0x00 });
                    if (response.IsSuccess) {
                        uid = response.Data;
                    }
                }
            } catch (Exception ex) {
                logger.Debug(ex);
            }
            return (uid);
        }

        public static bool IsHPKICardExist()
        {
            logger.Debug("IsHPKICardExist");
            bool ret = false;
            try {
                using (var reader = new ICReader()) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(APDU_SELECT_AUTH_AP)).IsSuccess == true)
                        return true;

                    if (reader.SendandResponse(gebo.NFC.Common.HexStringToBytes(APDU_SELECT_SIG_AP)).IsSuccess == true)
                        return true;

                    throw (new Exception("SELECT AP Error"));
                }
            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (ret);
        }

        // Auth
        public static byte[] GetAuthCert()
        {
            logger.Debug("<<<GetAuthenticationCertificate>>>");
            return (getEF(APDU_SELECT_AUTH_AP,APDU_SELECT_AUTH_CERT));
        }

        public static byte[] GetAuthPublicKey()
        {
            logger.Debug("<<<GetAuthenticationPublicKey>>>");
            var cert = HPKIReader.GetAuthCert();
            if (cert != null) {
                return (gebo.NFC.Cert.GetPublicKey(cert));
            }
            return null;
        }

        public static int GetAuthPINRetryCount()
        {
            logger.Debug("<<<GetAuthenticationPINRetryCount>>>");
            return (getPINRetryCount(APDU_SELECT_AUTH_AP,APDU_SELECT_AUTH_PIN));
        }

        public static byte[] SignAuthInPKCS1(string pin, string targetFile)
        {
            return (sigUsingPrivateKey(pin, targetFile, APDU_SELECT_AUTH_AP, APDU_SELECT_AUTH_PIN, APDU_SELECT_AUTH_KEY));
        }

        public static byte[] SignAuthInPKCS1(string pin, byte[] targetData)
        {
            // SHA1(baseData)
            System.Security.Cryptography.SHA1 sha = new System.Security.Cryptography.SHA1CryptoServiceProvider();
            var digestSHA1 = sha.ComputeHash(targetData);

            return (signature(pin, digestSHA1, APDU_SELECT_AUTH_AP, APDU_SELECT_AUTH_PIN, APDU_SELECT_AUTH_KEY, true));
        }

        public static byte[] SignUsingAuthPrivateKey(string pin, byte[] targetData)
        {
            return (signature(pin, targetData, APDU_SELECT_AUTH_AP, APDU_SELECT_AUTH_PIN, APDU_SELECT_AUTH_KEY, false));
        }

        // Sig
        public static byte[] GetSigCert()
        {
            logger.Debug("<<<GetSignatureCertificate>>>");
            return (getEF(APDU_SELECT_SIG_AP, APDU_SELECT_SIG_CERT));
        }

        public static byte[] GetSigPublicKey()
        {
            logger.Debug("<<<GetSigPublicKey>>>");
            var cert = HPKIReader.GetSigCert();
            if (cert != null) {
                return (gebo.NFC.Cert.GetPublicKey(cert));
            }
            return null;
        }

        public static int GetSigPINRetryCount()
        {
            logger.Debug("<<<GetSigPINRetryCount>>>");
            return (getPINRetryCount(APDU_SELECT_SIG_AP,APDU_SELECT_SIG_PIN));
        }

        public static byte[] SignSigInPKCS1(string pin, string targetFile)
        {
            return (sigUsingPrivateKey(pin, targetFile, APDU_SELECT_SIG_AP, APDU_SELECT_SIG_PIN, APDU_SELECT_SIG_KEY));
        }

    }
}


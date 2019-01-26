using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace TestUI01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private string getWorkDir()
        {
            string path = textBoxWorkDir.Text;
            if (string.IsNullOrEmpty(path)) {
                return (".");
            }

            if (System.IO.Directory.Exists(path) == false) {
                System.IO.Directory.CreateDirectory(path);
            }
            return path;
        }

        private void buttonCheckCard_Click(object sender, RoutedEventArgs e)
        {
            if (gebo.HPKIReaderLib.HPKIReader.IsHPKICardExist()) {
                MessageBox.Show("Check HPKI Success!");
            } else {
                MessageBox.Show("Check HPKI Failed!");
            }
        }

        private void buttonGetUID_Click(object sender, RoutedEventArgs e)
        {
            var uid = gebo.HPKIReaderLib.HPKIReader.GetCardUID();
            if( uid != null) {
                MessageBox.Show(gebo.NFC.Common.BytesToHexString(uid));
            } else {
                MessageBox.Show("GetCardUID Failed!");
            }
        }

        private void buttonGetAuthenticationCertificate_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = gebo.HPKIReaderLib.HPKIReader.GetAuthCert();

            if (der != null) {

                // Export
                System.IO.File.WriteAllBytes(workDir + @"\HPKI_Auth_Cert.der", der);

                gebo.NFC.Common.ExportHextoFile(workDir + @"\HPKI_Auth_Cert.hex", der.ToArray());

                var pem = gebo.NFC.Common.ConvertCertificateDERtoPEM(der.ToArray());
                System.IO.File.WriteAllText(workDir + @"\HPKI_Auth_Cert.pem", pem);

                MessageBox.Show("Get Auth Cert Success!");
            } else {
                MessageBox.Show("Get Auth Cert Failed!");
            }
        }

        private void buttonGetAuthenticationPublicKey_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = gebo.HPKIReaderLib.HPKIReader.GetAuthPublicKey();
            if (der != null) {
                System.IO.File.WriteAllBytes(workDir + @"\HPKI_Auth_PublicKey.der", der);

                var pem = gebo.NFC.Common.ConvertPublicKeyDERtoPEM(der);
                System.IO.File.WriteAllText(workDir + @"\HPKI_Auth_PublicKey.pem", pem);

                MessageBox.Show("Get Auth Public Key Success!");
            } else {
                MessageBox.Show("Get Auth Public Key Failed!");
            }
        }

        private void buttonGetSignatureCertificate_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = gebo.HPKIReaderLib.HPKIReader.GetSigCert();

            if (der != null) {

                // Export
                System.IO.File.WriteAllBytes(workDir + @"\HPKI_Sig_Cert.der", der);

                gebo.NFC.Common.ExportHextoFile(workDir + @"\HPKI_Sig_Cert.hex", der.ToArray());

                var pem = gebo.NFC.Common.ConvertCertificateDERtoPEM(der.ToArray());
                System.IO.File.WriteAllText(workDir + @"\HPKI_Sig_Cert.pem", pem);

                MessageBox.Show("Get Sig Cert Success!");
            } else {
                MessageBox.Show("Get Sig Cert Failed!");
            }

        }

        private void buttonGetObjects_Click(object sender, RoutedEventArgs e)
        {
            gebo.HPKIReaderLib.HPKIReader.GetCardObjectsJISX6320();
        }

        private void buttonGetAuthenticationPINRetryCount_Click(object sender, RoutedEventArgs e)
        {
            var count = gebo.HPKIReaderLib.HPKIReader.GetAuthPINRetryCount();
            MessageBox.Show(string.Format($"Authentication PIN Retry -> {count}"));
        }

        private void buttonSignAuthPKCS1_Click(object sender, RoutedEventArgs e)
        {
            if (textBoxAuthPIN.Text.Length <= 0) {
                MessageBox.Show("Auth PIN を入力してください");
                return;
            } else {
                var count = gebo.HPKIReaderLib.HPKIReader.GetAuthPINRetryCount();
                if (count < 0) {
                    MessageBox.Show("Error");
                }

                if (MessageBox.Show(string.Format($"PIN={textBoxAuthPIN.Text}\r\n\r\nAuthentication PIN Retry は {count} です。\r\n続けますか？"), "", MessageBoxButton.YesNo) != MessageBoxResult.Yes) {
                    return;
                }
            }

            var workDir = getWorkDir();

            string file = "";
            {
                var dialog = new Microsoft.Win32.OpenFileDialog();
                if (dialog.ShowDialog() == true) {
                    file = dialog.FileName;
                } else {
                    return;
                }
            }

            // ファイルの電子署名を得る
            var sig = gebo.HPKIReaderLib.HPKIReader.SignAuthInPKCS1(textBoxAuthPIN.Text, file);
            if (sig != null) {
                // Export
                var title = System.IO.Path.GetFileNameWithoutExtension(file);
                System.IO.File.WriteAllBytes(workDir + $@".\{title}_HPKI_Auth_PKCS1.sig", sig);

                MessageBox.Show("Signature using Auth Private Key Success!");
            } else {
                MessageBox.Show("Signature using Auth Private Key Failed!");
            }

        }

        private void buttonSignUsingAuthenticationPrivateKey_Click(object sender, RoutedEventArgs e)
        {
            if (textBoxAuthPIN.Text.Length <= 0) {
                MessageBox.Show("Auth PIN を入力してください");
                return;
            } else {
                var count = gebo.HPKIReaderLib.HPKIReader.GetAuthPINRetryCount();
                if (count < 0) {
                    MessageBox.Show("Error");
                }

                if (MessageBox.Show(string.Format($"PIN={textBoxAuthPIN.Text}\r\n\r\nAuthentication PIN Retry は {count} です。\r\n続けますか？"), "", MessageBoxButton.YesNo) != MessageBoxResult.Yes) {
                    return;
                }
            }

            var workDir = getWorkDir();

            string file = "";
            {
                var dialog = new Microsoft.Win32.OpenFileDialog();
                if (dialog.ShowDialog() == true) {
                    file = dialog.FileName;
                } else {
                    return;
                }
            }

            System.IO.StreamReader sr = new System.IO.StreamReader(file, Encoding.GetEncoding("Shift_JIS"));
            string text = sr.ReadToEnd();
            byte[] target = System.Text.Encoding.ASCII.GetBytes(text);

            var sig = gebo.HPKIReaderLib.HPKIReader.SignUsingAuthPrivateKey(textBoxAuthPIN.Text, target);
            if (sig != null) {
                // Export
                var title = System.IO.Path.GetFileNameWithoutExtension(file);
                System.IO.File.WriteAllBytes(workDir + $@".\{title}_HPKI_Sig_using_Auth_PrivateKey.sig", sig);

                MessageBox.Show("Encrypt using Auth Private Key Success!");
            } else {
                MessageBox.Show("Encrypt using Auth Private Key Failed!");
            }
        }

        private void buttonVerify_Click(object sender, RoutedEventArgs e)
        {
            try {
                var pubkeyder = System.IO.File.ReadAllBytes(textPubKey.Text);

                byte[] signature = System.IO.File.ReadAllBytes(textSig.Text);

                string targetFile = textTargetFile.Text;

                if (gebo.HPKIReaderLib.Verify.VerifySignature(pubkeyder, signature, targetFile)) {
                    MessageBox.Show("Verify Success!");
                } else {
                    MessageBox.Show("Verify Failed!");
                }
            } catch (Exception) {
                MessageBox.Show("Verify Failed.Exception Error has occurred");
            }
        }

        private void buttonPubKey_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true) {
                textPubKey.Text = dialog.FileName;
            }
        }

        private void buttonTargetFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true) {
                textTargetFile.Text = dialog.FileName;
            }
        }

        private void buttonSig_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true) {
                textSig.Text = dialog.FileName;
            }
        }

        private void buttonGetSigPublicKey_Click(object sender, RoutedEventArgs e)
        {
            var workDir = getWorkDir();

            var der = gebo.HPKIReaderLib.HPKIReader.GetSigPublicKey();
            if (der != null) {
                System.IO.File.WriteAllBytes(workDir + @"\HPKI_Sig_PublicKey.der", der);

                var pem = gebo.NFC.Common.ConvertPublicKeyDERtoPEM(der);
                System.IO.File.WriteAllText(workDir + @"\HPKI_Sig_PublicKey.pem", pem);

                MessageBox.Show("Get Sig Public Key Success!");
            } else {
                MessageBox.Show("Get Sig Public Key Failed!");
            }

        }

        private void buttonGetSigPINRetryCount_Click(object sender, RoutedEventArgs e)
        {
            var count = gebo.HPKIReaderLib.HPKIReader.GetSigPINRetryCount();
            MessageBox.Show(string.Format($"Sig PIN Retry -> {count}"));

        }

        private void buttonSignSigPKCS1_Click(object sender, RoutedEventArgs e)
        {
            if (textBoxSigPIN.Text.Length <= 0) {
                MessageBox.Show("Sig PIN を入力してください");
                return;
            } else {
                var count = gebo.HPKIReaderLib.HPKIReader.GetSigPINRetryCount();
                if (count < 0) {
                    MessageBox.Show("Error");
                }

                if (MessageBox.Show(string.Format($"PIN={textBoxSigPIN.Text}\r\n\r\nSig PIN Retry は {count} です。\r\n続けますか？"), "", MessageBoxButton.YesNo) != MessageBoxResult.Yes) {
                    return;
                }
            }

            var workDir = getWorkDir();

            string file = "";
            {
                var dialog = new Microsoft.Win32.OpenFileDialog();
                if (dialog.ShowDialog() == true) {
                    file = dialog.FileName;
                } else {
                    return;
                }
            }

            // ファイルの電子署名を得る
            var sig = gebo.HPKIReaderLib.HPKIReader.SignSigInPKCS1(textBoxSigPIN.Text, file);
            if (sig != null) {
                // Export
                var title = System.IO.Path.GetFileNameWithoutExtension(file);
                System.IO.File.WriteAllBytes(workDir + $@".\{title}_HPKI_Sig_PKCS1.sig", sig);

                MessageBox.Show("Sign Success!");
            } else {
                MessageBox.Show("Sign Failed!");
            }

        }
    }
}

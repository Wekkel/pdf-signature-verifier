using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;

// Correcte 'using' statements voor de moderne iText API
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Commons.Bouncycastle.Cert;

namespace PdfSignatureVerifier.App
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void SelectPdfButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "PDF Files|*.pdf",
                Title = "Selecteer een PDF-bestand"
            };

            if (openFileDialog.ShowDialog() != true)
            {
                return;
            }

            string filePath = openFileDialog.FileName;
            InfoTextBlock.Text = $"Analyse gestart voor:\n{Path.GetFileName(filePath)}";

            try
            {
                using (var pdfReader = new PdfReader(filePath))
                using (var pdfDoc = new PdfDocument(pdfReader))
                {
                    var signatureUtil = new SignatureUtil(pdfDoc);
                    var signatureNames = signatureUtil.GetSignatureNames();

                    if (signatureNames.Count == 0)
                    {
                        MessageBox.Show("Geen cryptografische handtekeningen gevonden in dit document.", "Analyse Resultaat", MessageBoxButton.OK, MessageBoxImage.Information);
                        return;
                    }

                    string resultMessage = $"Er zijn {signatureNames.Count} handtekening(en) gevonden:\n\n";

                    foreach (var name in signatureNames)
                    {
                        // --- DE FINALE, CORRECTE WORKFLOW ---

                        // Stap 1: Gebruik de SignatureUtil om de cryptografische data te lezen.
                        // DEZE METHODE IS VAN signatureUtil, NIET van PdfSignature.
                        PdfPKCS7 pkcs7 = signatureUtil.ReadSignatureData(name);

                        // Stap 2: Verifieer de handtekening met de data die we net hebben gelezen.
                        bool isValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

                        // Stap 3: Haal het certificaat op van hetzelfde pkcs7 object.
                        IX509Certificate signingCert = pkcs7.GetSigningCertificate();

                        var subjectFields = CertificateInfo.GetSubjectFields(signingCert);
                        string signerName = subjectFields?.GetField("CN") ?? "Onbekende Ondertekenaar";

                        string validityStatus = isValid ? "GELDIG" : "ONGELDIG";
                        resultMessage += $"- Ondertekend door: {signerName} (Status: {validityStatus})\n";
                    }

                    MessageBox.Show(resultMessage, "Analyse Resultaat");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Er is een fout opgetreden bij het lezen van de PDF:\n\n{ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
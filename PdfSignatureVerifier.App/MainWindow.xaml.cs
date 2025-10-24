using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using System.Windows.Media;

// iText & BouncyCastle using statements
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Commons.Bouncycastle.Cert;

namespace PdfSignatureVerifier.App
{
    // Een class om de resultaten van onze analyse netjes te structureren
    public class AnalysisResult
    {
        public enum SignatureLevel { QES, AES, SES }

        public SignatureLevel Level { get; set; }
        public string Title { get; set; }
        public string Explanation { get; set; }
        public SolidColorBrush Color { get; set; }
        public string SignerInfo { get; set; } = string.Empty;
    }

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

            if (openFileDialog.ShowDialog() != true) return;

            string filePath = openFileDialog.FileName;

            // Voer de analyse uit en krijg een gestructureerd resultaat terug
            AnalysisResult result = PerformAnalysis(filePath);

            // Update de UI met de resultaten
            UpdateUIWithResult(result, filePath);
        }

        private AnalysisResult PerformAnalysis(string filePath)
        {
            try
            {
                using (var pdfReader = new PdfReader(filePath))
                using (var pdfDoc = new PdfDocument(pdfReader))
                {
                    var signatureUtil = new SignatureUtil(pdfDoc);
                    var signatureNames = signatureUtil.GetSignatureNames();

                    if (signatureNames.Count == 0)
                    {
                        // Geen cryptografische handtekening gevonden -> SES
                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.SES,
                            Title = "Geen Geavanceerde/Gekwalificeerde Handtekening",
                            Color = new SolidColorBrush(Colors.Orange),
                            Explanation = "Dit programma heeft geen cryptografisch geldige elektronische handtekening (AES of QES) gevonden.\n\n" +
                                          "Wat betekent dit?\n" +
                                          "De PDF kan nog steeds een Standaard Elektronische Handtekening (SES) bevatten. Denk hierbij aan een ingeplakte scan van een 'natte' handtekening of een handtekening gezet met een muis of digitale pen. Dit programma kan de geldigheid van zo'n handtekening niet controleren.\n\n" +
                                          "Wat moet u zelf controleren?\n" +
                                          "Beoordeel visueel of u de handtekening in het document vertrouwt en of deze van de juiste persoon afkomstig lijkt te zijn."
                        };
                    }

                    // Voor nu doen we een simpele cryptografische check.
                    // De ECHTE QES/AES check is de volgende stap.
                    // We simuleren het resultaat voor nu.
                    var name = signatureNames[0]; // We analyseren de eerste handtekening
                    PdfPKCS7 pkcs7 = signatureUtil.ReadSignatureData(name);
                    bool isValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();
                    IX509Certificate signingCert = pkcs7.GetSigningCertificate();
                    string signerName = CertificateInfo.GetSubjectFields(signingCert)?.GetField("CN") ?? "Onbekende Ondertekenaar";

                    // TODO: Implementeer hier de ECHTE check tegen de EU Trust List.
                    // Voor nu, simuleren we een AES.
                    if (isValid)
                    {
                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.AES,
                            Title = "Geavanceerde Handtekening (AES)",
                            Color = new SolidColorBrush(Colors.DodgerBlue),
                            SignerInfo = $"Ondertekend door: {signerName}",
                            Explanation = "Het document bevat een cryptografisch geldige handtekening. Dit wordt geclassificeerd als een Geavanceerde Elektronische Handtekening (AES).\n\n" +
                                          "Wat betekent dit?\n" +
                                          "Een AES is uniek verbonden met de ondertekenaar en het document. Wijzigingen in het document ná ondertekening kunnen worden gedetecteerd. Deze handtekening is echter (nog) niet geverifieerd tegen de officiële EU Trust List en telt daarom niet als 'Gekwalificeerd'.\n\n" +
                                          // TODO: Implementeer SSCD (token) check
                                          "De analyse kon nog niet vaststellen of er een hardware token (zoals een smartcard) is gebruikt."
                        };
                    }
                    else
                    {
                        // In een echt scenario zou dit een 'Ongeldige Handtekening' zijn
                        return new AnalysisResult { Level = AnalysisResult.SignatureLevel.SES, Title = "ONGELDIGE Handtekening", Color = new SolidColorBrush(Colors.Red), Explanation = "De handtekening in het document is cryptografisch ONGELDIG. Het document is mogelijk aangepast na ondertekening." };
                    }
                }
            }
            catch (Exception)
            {
                return new AnalysisResult { Level = AnalysisResult.SignatureLevel.SES, Title = "Fout bij Analyse", Color = new SolidColorBrush(Colors.Red), Explanation = "Er is een technische fout opgetreden bij het lezen van de PDF. Het is mogelijk dat het bestand corrupt is of geen standaard PDF-structuur heeft." };
            }
        }

        private void UpdateUIWithResult(AnalysisResult result, string filePath)
        {
            // Update het resultaatpaneel
            ResultPanel.BorderBrush = result.Color;
            ResultTitle.Text = result.Title;
            ResultTitle.Foreground = result.Color;
            ResultFilename.Text = $"Bestand: {Path.GetFileName(filePath)}\n{result.SignerInfo}";
            ResultExplanation.Text = result.Explanation;

            // Maak het resultaatpaneel zichtbaar
            ResultPanel.Visibility = Visibility.Visible;

            // Laad de PDF in de viewer
            // De 'file:///' prefix is belangrijk om de browser te vertellen dat het een lokaal bestand is
            PdfWebView.Source = new Uri($"file:///{filePath}");
        }
    }
}
using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Collections.Generic;
using Org.BouncyCastle.X509;

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
        private readonly EutlService _eutlService;

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

                    var name = signatureNames[0]; // We analyseren de eerste handtekening
                    PdfPKCS7 pkcs7 = signatureUtil.ReadSignatureData(name);
                    IX509Certificate signingCert = pkcs7.GetSigningCertificate();
                    string signerName = CertificateInfo.GetSubjectFields(signingCert)?.GetField("CN") ?? "Onbekende Ondertekenaar";

                    // De basisintegriteitscheck
                    bool isSignatureValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

                    if (isSignatureValid)
                    {
                        // Handtekening is cryptografisch geldig -> AES (voor nu)
                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.AES,
                            Title = "Geavanceerde Handtekening (AES)",
                            Color = new SolidColorBrush(Colors.DodgerBlue),
                            SignerInfo = $"Ondertekend door: {signerName}",
                            Explanation = "Het document bevat een cryptografisch geldige handtekening. Dit wordt geclassificeerd als een Geavanceerde Elektronische Handtekening (AES).\n\n" +
                                          "Wat betekent dit?\n" +
                                          "Een AES is uniek verbonden met de ondertekenaar en het document. Wijzigingen in het document ná ondertekening kunnen worden gedetecteerd. Deze handtekening is echter (nog) niet geverifieerd tegen de officiële EU Trust List en telt daarom niet als 'Gekwalificeerd'."
                        };
                    }
                    else
                    {
                        // De basisconclusie is dat de handtekening ongeldig is.
                        // Laten we nu een lijst van specifieke problemen voor de gebruiker verzamelen.
                        var issues = new List<string>();

                        // Detail 1: Controleer de geldigheid van het certificaat op de datum van ondertekening.
                        // Dit doen we in een 'try-catch' blok, want de analyse kan zelf een fout geven.
                        try
                        {
                            // Converteer het iText certificaat naar een volledig BouncyCastle certificaat
                            var parser = new X509CertificateParser();
                            var bouncyCastleCert = parser.ReadCertificate(signingCert.GetEncoded());

                            // Laat BouncyCastle de datums controleren. Als dit een fout geeft, vangen we die op.
                            bouncyCastleCert.CheckValidity(pkcs7.GetSignDate());
                        }
                        catch (Exception certEx)
                        {
                            // We vonden een specifiek probleem met de geldigheid van het certificaat.
                            issues.Add($"Het gebruikte certificaat was niet geldig op de datum van ondertekening. Details: {certEx.Message}");
                        }

                        // Detail 2: Controleer of de handtekening het hele document dekt.
                        if (!signatureUtil.SignatureCoversWholeDocument(name))
                        {
                            issues.Add("De handtekening dekt niet het volledige document. Dit kan betekenen dat er later niet-ondertekende content is toegevoegd.");
                        }

                        // Als we na de detail-checks nog steeds geen specifieke reden hebben,
                        // geven we de meest waarschijnlijke algemene reden.
                        if (issues.Count == 0)
                        {
                            issues.Add("De cryptografische integriteit van de handtekening is verbroken. Dit duidt er meestal op dat het document is gewijzigd NADAT de handtekening is geplaatst.");
                        }

                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.SES,
                            Title = "ONGELDIGE Handtekening Gevonden",
                            Color = new SolidColorBrush(Colors.Red),
                            SignerInfo = $"Ondertekenaar (volgens certificaat): {signerName}",
                            Explanation = "Er is een cryptografische handtekening gevonden, maar deze is ONGELDIG. De integriteit en/of authenticiteit van het document is niet gegarandeerd.\n\n" +
                                          $"Gevonden Problemen:\n- {string.Join("\n- ", issues)}"
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return new AnalysisResult { Level = AnalysisResult.SignatureLevel.SES, Title = "Fout bij Analyse", Color = new SolidColorBrush(Colors.Red), Explanation = $"Er is een technische fout opgetreden bij het lezen van de handtekening: {ex.Message}" };
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


        private async void UpdateTrustListStatusAsync()
        {
            TrustListStatusText.Text = "Bezig met bijwerken EU Trust List...";
            string status = await _eutlService.UpdateTrustListAsync();
            TrustListStatusText.Text = status;
        }

    }
}
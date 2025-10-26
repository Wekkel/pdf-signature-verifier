using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;

// Correcte 'using' statements voor de geïnstalleerde bibliotheken
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Commons.Bouncycastle.Cert; // iText's interne BouncyCastle interface
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace PdfSignatureVerifier.App
{
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
            _eutlService = new EutlService();
            InitializeBackendAsync();
        }

        private async void InitializeBackendAsync()
        {
            await PdfWebView.EnsureCoreWebView2Async(null);

            // Functie om zowel de zichtbare als de onzichtbare log bij te werken
            void UpdateLog(string text)
            {
                TrustListStatusText.Text = text;
                LogTextBox.Text = text; // Houd de volledige log bij in de verborgen TextBox
            }

            // Stap 1: Laad direct de cache
            string initialStatus = _eutlService.LoadFromCache();
            UpdateLog(initialStatus);

            // Stap 2: Probeer op de achtergrond een update uit te voeren.
            string currentLog = LogTextBox.Text;
            UpdateLog(currentLog + " (Bezig met zoeken naar updates...)");

            string updateStatus = await _eutlService.UpdateTrustListAsync();

            // Stap 3: Toon het definitieve resultaat
            UpdateLog(updateStatus);
        }

        private void SelectPdfButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog { Filter = "PDF Files|*.pdf", Title = "Selecteer een PDF-bestand" };
            if (openFileDialog.ShowDialog() != true) return;
            var result = PerformAnalysis(openFileDialog.FileName);
            UpdateUIWithResult(result, openFileDialog.FileName);
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

                    if (!signatureNames.Any())
                    {
                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.SES,
                            Title = "Geen Cryptografische Handtekening",
                            Color = new SolidColorBrush(Colors.Orange),
                            Explanation = "Dit programma heeft geen cryptografisch geldige handtekening (AES of QES) gevonden.\n\n" +
                                          "Wat betekent dit?\n" +
                                          "De PDF kan een Standaard Elektronische Handtekening (SES) bevatten, zoals een scan van een 'natte' handtekening. Dit programma kan de geldigheid hiervan niet controleren. U dient dit visueel te beoordelen."
                        };
                    }

                    var name = signatureNames.First();
                    PdfPKCS7 pkcs7 = signatureUtil.ReadSignatureData(name);
                    IX509Certificate signingCert = pkcs7.GetSigningCertificate();
                    string signerName = CertificateInfo.GetSubjectFields(signingCert)?.GetField("CN") ?? "Onbekend";
                    bool isValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

                    if (isValid)
                    {
                        bool isQES = IsCertificateChainQualified(pkcs7);
                        if (isQES)
                        {
                            return new AnalysisResult
                            {
                                Level = AnalysisResult.SignatureLevel.QES,
                                Title = "Gekwalificeerde Handtekening (QES)",
                                Color = new SolidColorBrush(Colors.LightGreen),
                                SignerInfo = $"Ondertekend door: {signerName}",
                                Explanation = "Deze handtekening is cryptografisch geldig én is geverifieerd tegen de officiële EU Trust List. Dit is een Gekwalificeerde Elektronische Handtekening (QES).\n\n" +
                                              "Wat betekent dit?\n" +
                                              "Een QES heeft dezelfde juridische status als een handgeschreven handtekening in de hele Europese Unie. Het biedt het hoogste niveau van zekerheid."
                            };
                        }
                        else
                        {
                            return new AnalysisResult
                            {
                                Level = AnalysisResult.SignatureLevel.AES,
                                Title = "Geavanceerde Handtekening (AES)",
                                Color = new SolidColorBrush(Colors.DodgerBlue),
                                SignerInfo = $"Ondertekend door: {signerName}",
                                Explanation = "Het document bevat een cryptografisch geldige handtekening. Dit wordt geclassificeerd als een Geavanceerde Elektronische Handtekening (AES).\n\n" +
                                              "Wat betekent dit?\n" +
                                              "De handtekening is geldig en het document is niet gewijzigd na ondertekening. Deze handtekening is echter niet geverifieerd tegen de EU Trust List en telt daarom niet als 'Gekwalificeerd'."
                            };
                        }
                    }
                    else
                    {
                        // De gedetailleerde foutanalyse
                        var issues = new List<string>();
                        try
                        {
                            var parser = new X509CertificateParser();
                            var bouncyCastleCert = parser.ReadCertificate(signingCert.GetEncoded());
                            bouncyCastleCert.CheckValidity(pkcs7.GetSignDate());
                        }
                        catch (Exception certEx)
                        {
                            issues.Add($"Het gebruikte certificaat was ongeldig op het moment van ondertekenen. Reden: {certEx.Message}");
                        }
                        if (!signatureUtil.SignatureCoversWholeDocument(name))
                        {
                            issues.Add("De handtekening dekt niet het volledige document.");
                        }
                        if (!issues.Any())
                        {
                            issues.Add("De cryptografische integriteit is verbroken (document is waarschijnlijk gewijzigd na ondertekening).");
                        }

                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.SES,
                            Title = "ONGELDIGE Handtekening Gevonden",
                            Color = new SolidColorBrush(Colors.Red),
                            SignerInfo = $"Ondertekenaar (volgens certificaat): {signerName}",
                            Explanation = "Er is een cryptografische handtekening gevonden, maar deze is ONGELDIG. De integriteit van het document is niet gegarandeerd.\n\n" +
                                          $"Gevonden Problemen:\n- {string.Join("\n- ", issues)}"
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return new AnalysisResult { Level = AnalysisResult.SignatureLevel.SES, Title = "Fout bij Analyse", Color = new SolidColorBrush(Colors.Red), Explanation = $"Een technische fout heeft de analyse verhinderd: {ex.Message}" };
            }
        }

        private bool IsCertificateChainQualified(PdfPKCS7 pkcs7)
        {
            // Als de EUTL-lijst niet geladen is, kunnen we niets valideren.
            if (_eutlService.TrustedCertificates == null || !_eutlService.TrustedCertificates.Any())
            {
                return false;
            }

            try
            {
                var parser = new X509CertificateParser();

                // 1. Haal de certificaatketen uit de handtekening in de PDF.
                var certChainFromPdf = pkcs7.GetSignCertificateChain()
                    .Select(c => parser.ReadCertificate(c.GetEncoded()))
                    .ToList();

                if (!certChainFromPdf.Any())
                {
                    return false;
                }

                // 2. Maak een 'HashSet' van onze vertrouwde EUTL-certificaten voor snelle lookups.
                var trustedEutlCerts = _eutlService.TrustedCertificates
                    .Select(c => parser.ReadCertificate(c.GetEncoded()))
                    .ToHashSet();

                // 3. De validatie: we controleren de keten van onder naar boven (van ondertekenaar naar root).
                for (int i = 0; i < certChainFromPdf.Count; i++)
                {
                    var subjectCert = certChainFromPdf[i];

                    // A. Is dit certificaat ZELF direct vertrouwd in de EUTL?
                    if (trustedEutlCerts.Contains(subjectCert))
                    {
                        // Ja! We hebben een match. Dit is een QES.
                        return true;
                    }

                    // B. Zo niet, is de UITGEVER (issuer) van dit certificaat vertrouwd?
                    // We zoeken naar een volgend certificaat in de keten dat deze heeft ondertekend.
                    var issuerCert = (i + 1 < certChainFromPdf.Count) ? certChainFromPdf[i + 1] : null;
                    if (issuerCert != null)
                    {
                        try
                        {
                            // Controleer of de handtekening klopt.
                            subjectCert.Verify(issuerCert.GetPublicKey());
                            // De keten is tot hier geldig. De loop gaat verder om de issuer te checken.
                        }
                        catch (Exception)
                        {
                            // De keten is hier verbroken. Het is geen geldige keten.
                            return false;
                        }
                    }
                }

                // Als we de hele keten hebben doorlopen en geen enkel certificaat
                // zat in de EUTL-lijst, dan is het geen QES.
                return false;
            }
            catch
            {
                // Bij elke fout tijdens de validatie, gaan we uit van het veiligste: geen QES.
                return false;
            }
        }

        private void UpdateUIWithResult(AnalysisResult result, string filePath)
        {
            ResultPanel.BorderBrush = result.Color;
            ResultTitle.Text = result.Title;
            ResultTitle.Foreground = result.Color;
            ResultFilename.Text = $"Bestand: {Path.GetFileName(filePath)}\n{result.SignerInfo}";
            ResultExplanation.Text = result.Explanation;
            ResultPanel.Visibility = Visibility.Visible;
            PdfWebView.Source = new Uri($"file:///{filePath}");
        }

        private void CopyLog_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(LogTextBox.Text);
        }
    }
}
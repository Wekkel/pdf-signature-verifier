using iText.Commons.Bouncycastle.Cert; // iText's interne BouncyCastle interface
// Correcte 'using' statements voor de geïnstalleerde bibliotheken
using iText.Kernel.Pdf;
using iText.Layout.Element;
using iText.Signatures;
using Microsoft.Win32;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using static System.Net.Mime.MediaTypeNames;

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

        // FOUT BLOK
        // CORRECT BLOK
        private async void InitializeBackendAsync()
        {
            // Stap 1: Pas de UI aan om de 'laden' status te tonen
            SelectPdfButton.IsEnabled = false;
            SelectPdfButton.Content = "Lijsten Laden..."; // Geef directe feedback op de knop

            await PdfWebView.EnsureCoreWebView2Async(null);

            void UpdateLog(string text)
            {
                TrustListStatusText.Text = text;
                LogTextBox.Text = text;
            }

            // Stap 2: Laad de cache
            string initialStatus = _eutlService.LoadFromCache();
            UpdateLog(initialStatus);

            var cacheMaxAge = TimeSpan.FromDays(7);
            bool isCacheMissing = !_eutlService.TrustedCertificates.Any();
            bool isCacheOld = (DateTime.UtcNow - _eutlService.LastUpdated) > cacheMaxAge;

            // Stap 3: Bepaal of een update nodig is
            if (isCacheMissing || isCacheOld)
            {
                string reason = isCacheMissing ? "Geen cache gevonden" : "Cache is verouderd";
                UpdateLog(LogTextBox.Text + $" ({reason}, bezig met downloaden...)");

                // DE CORRECTIE: Maak de callback functie en geef hem mee aan de methode
                Action<string> downloadCallback = (status) => Dispatcher.Invoke(() => SelectPdfButton.Content = status);
                string updateStatus = await _eutlService.UpdateTrustListAsync(downloadCallback);

                UpdateLog(updateStatus);
            }

            // Stap 4: Herstel de knop naar zijn normale staat
            SelectPdfButton.IsEnabled = true;
            SelectPdfButton.Content = "Selecteer en Analyseer PDF";
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
                        return new AnalysisResult { /* ... uw SES-tekst ... */ };
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
                            // Het is een AES. Nu voegen we de waarschuwing toe als de EUTL leeg is.
                            string eutlWarning = string.Empty;
                            if (!_eutlService.TrustedCertificates.Any())
                            {
                                eutlWarning = "\n\nWAARSCHUWING: De EU Trust List kon niet worden geladen. Deze handtekening kon daarom niet op QES-status worden gecontroleerd en wordt als AES weergegeven.";
                            }

                            return new AnalysisResult
                            {
                                Level = AnalysisResult.SignatureLevel.AES,
                                Title = "Geavanceerde Handtekening (AES)",
                                Color = new SolidColorBrush(Colors.DodgerBlue),
                                SignerInfo = $"Ondertekend door: {signerName}",
                                Explanation = "Het document bevat een cryptografisch geldige handtekening. Dit wordt geclassificeerd als een Geavanceerde Elektronische Handtekening (AES).\n\n" +
                                              "Wat betekent dit?\n" +
                                              "De handtekening is geldig en het document is niet gewijzigd na ondertekening. Deze handtekening is echter niet geverifieerd tegen de EU Trust List en telt daarom niet als 'Gekwalificeerd'." +
                                              eutlWarning // Voeg de waarschuwing hier toe
                            };
                        }
                    }
                    else
                    {
                        // De logica voor ongeldige handtekeningen...
                        // ... (deze code blijft hetzelfde als in het vorige, werkende antwoord)
                        var issues = new List<string>();
                        // ... etc. ...
                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.SES,
                            Title = "ONGELDIGE Handtekening Gevonden",
                            Color = new SolidColorBrush(Colors.Red),
                            SignerInfo = $"Ondertekenaar (volgens certificaat): {signerName}",
                            Explanation = $"Er is een cryptografische handtekening gevonden, maar deze is ONGELDIG...\n\n" +
                                          $"Gevonden Problemen:\n- {string.Join("\n- ", issues)}"
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return new AnalysisResult { /* ... uw foutafhandeling ... */ };
            }
        }


        private bool IsCertificateChainQualified(PdfPKCS7 pkcs7)
        {
            if (_eutlService.TrustedCertificates == null || !_eutlService.TrustedCertificates.Any())
            {
                return false;
            }

            try
            {
                var parser = new X509CertificateParser();
                var crlParser = new X509CrlParser();

                var certChainFromPdf = pkcs7.GetSignCertificateChain()
                    .Select(c => parser.ReadCertificate(c.GetEncoded()))
                    .ToList();

                if (!certChainFromPdf.Any())
                {
                    return false;
                }

                // --- DE NIEUWE, DIRECTE CRL-CHECK ---
                // Maak een lijst van alle gedownloade CRL-objecten
                var allCrls = _eutlService.CrlCache.Values
                    .Select(crlData => crlParser.ReadCrl(crlData))
                    .ToList();

                // Controleer elk certificaat in de keten van de PDF
                foreach (var certInChain in certChainFromPdf)
                {
                    // Zoek de relevante CRLs voor dit certificaat (uitgegeven door dezelfde partij)
                    foreach (var crl in allCrls)
                    {
                        if (crl.IssuerDN.Equivalent(certInChain.IssuerDN))
                        {
                            if (crl.GetRevokedCertificate(certInChain.SerialNumber) != null)
                            {
                                // GEVONDEN OP ZWARTE LIJST!
                                // De hele keten is per definitie ongeldig.
                                return false;
                            }
                        }
                    }
                }
                // --- EINDE CRL-CHECK ---

                // Uw bestaande, werkende QES-anker check.
                var trustedEutlCerts = _eutlService.TrustedCertificates.ToHashSet();

                for (int i = 0; i < certChainFromPdf.Count; i++)
                {
                    var subjectCert = certChainFromPdf[i];

                    if (trustedEutlCerts.Contains(subjectCert))
                    {
                        try
                        {
                            for (int j = 0; j < i; j++)
                            {
                                certChainFromPdf[j].Verify(certChainFromPdf[j + 1].GetPublicKey());
                            }
                            return true;
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
                return false;
            }
            catch
            {
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
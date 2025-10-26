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
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
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

        public string TimestampInfo { get; set; } = string.Empty;
        public bool HasQualifiedTimestamp { get; set; } = false;

    }

    public partial class MainWindow : Window
    {
        private readonly EutlService _eutlService;
        private List<SignatureInfo> _allSignatures;
        private string _currentFilePath;

        public MainWindow()
        {
            InitializeComponent();
            _eutlService = new EutlService();
            InitializeBackendAsync();
        }


        private void AboutMenuItem_Click(object sender, RoutedEventArgs e)
        {
            AboutWindow aboutWindow = new AboutWindow();
            aboutWindow.ShowDialog(); // ShowDialog blokkeert de interactie met het hoofdvenster totdat de About-box is gesloten
        }

        private async void InitializeBackendAsync()
        {
            SelectPdfButton.IsEnabled = false;
            SetButtonMainText("Lijsten Laden...", false);

            await PdfWebView.EnsureCoreWebView2Async(null);

            void UpdateLog(string text)
            {
                TrustListStatusText.Text = text;
                LogTextBox.Text = text;
            }

            // Step 1: Load from cache
            string initialStatus = _eutlService.LoadFromCache();
            UpdateLog(initialStatus);

            var cacheMaxAge = TimeSpan.FromDays(7);
            bool isCacheMissing = !_eutlService.TrustedCertificates.Any();
            bool isCacheOld = (DateTime.UtcNow - _eutlService.LastUpdated) > cacheMaxAge;

            // Step 2: Update trust list AND CRLs if needed
            if (isCacheMissing || isCacheOld)
            {
                string reason = isCacheMissing ? "Geen cache gevonden" : "Cache is verouderd";
                UpdateLog(LogTextBox.Text + $" ({reason}, bezig met downloaden...)");

                Action<string> downloadCallback = (status) => Dispatcher.Invoke(() => SetButtonMainText(status, false));
                string updateStatus = await _eutlService.UpdateTrustListAsync(downloadCallback);

                UpdateLog(updateStatus);
            }
            // Step 3: NEW - Check if only the hash needs updating
            else if (_eutlService.HashNeedsUpdate(cacheMaxAge))
            {
                UpdateLog(LogTextBox.Text + " Hash is verouderd, opnieuw bouwen...");
                SetButtonMainText("Hash Bouwen...", false);

                // Rebuild hash from cached CRLs (fast, no download needed)
                await Task.Run(() => _eutlService.RebuildHashFromCache());

                UpdateLog($"EU lijsten geladen uit cache ({_eutlService.TrustedCertificates.Count} certs, {_eutlService.RevokedSerialNumbers.Count} ingetrokken serienummers). Hash bijgewerkt op {_eutlService.HashLastUpdated:dd-MM-yyyy HH:mm} UTC.");
            }
            else
            {
                // Both cache and hash are fresh
                UpdateLog($"EU lijsten geladen uit cache ({_eutlService.TrustedCertificates.Count} certs, {_eutlService.RevokedSerialNumbers.Count} ingetrokken serienummers). Laatst bijgewerkt: {_eutlService.LastUpdated:dd-MM-yyyy HH:mm} UTC.");
            }

            // Stap 4: Herstel de knop naar zijn normale staat
            SelectPdfButton.IsEnabled = true;
            SetButtonMainText("Selecteer en Analyseer PDF", true);
        }


        private void SelectPdfButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog { Filter = "PDF Files|*.pdf", Title = "Selecteer een PDF-bestand" };

            if (openFileDialog.ShowDialog() == true)
            {
                // Roep de centrale analysemethode aan
                StartAnalysis(openFileDialog.FileName);
            }
        }

        private void StartAnalysis(string filePath)
        {

            _currentFilePath = filePath; // remember the real path

            // 1. Reset de UI naar een 'Laden' staat.
            ResultPanel.Visibility = Visibility.Collapsed; 
            SelectPdfButton.IsEnabled = false;
            SetButtonMainText("Analyse Bezig...", false);

            // Laad de PDF alvast in de viewer
            if (File.Exists(filePath))
            {
                PdfWebView.Source = new Uri($"file:///{filePath}");
            }

            Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Background);

            // Analyseer ALLE handtekeningen
            _allSignatures = AnalyzeAllSignatures(filePath);

            if (_allSignatures.Any())
            {
                // Toon de lijst met handtekeningen
                SignatureListPanel.Visibility = Visibility.Visible;
                SignatureListBox.ItemsSource = _allSignatures;

                // Selecteer automatisch de eerste handtekening
                SignatureListBox.SelectedIndex = 0;
            }
            else
            {
                // Geen handtekeningen gevonden
                SignatureListPanel.Visibility = Visibility.Collapsed;
                var noSigResult = new AnalysisResult
                {
                    Level = AnalysisResult.SignatureLevel.SES,
                    Title = "Geen Cryptografische Handtekening",
                    Color = new SolidColorBrush(Colors.Orange),
                    Explanation = "Dit document bevat geen cryptografische handtekeningen..."
                };
                UpdateUIWithResult(noSigResult, filePath);
            }
            SelectPdfButton.IsEnabled = true;
            SetButtonMainText("Selecteer en Analyseer PDF", true);
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
                    // GEREPAREERDE BLOK
                    else
                    {
                        // De handtekening is cryptografisch ongeldig. Laten we de redenen verzamelen.
                        var issues = new List<string>();

                        // Detail 1: Controleer de geldigheid van het certificaat op de datum van ondertekening.
                        try
                        {
                            var parser = new X509CertificateParser();
                            var bouncyCastleCert = parser.ReadCertificate(signingCert.GetEncoded());
                            // Laat BouncyCastle de datums controleren.
                            bouncyCastleCert.CheckValidity(pkcs7.GetSignDate());
                        }
                        catch (Exception certEx)
                        {
                            issues.Add($"Het gebruikte certificaat was ongeldig op het moment van ondertekenen. Reden: {certEx.Message}");
                        }

                        // Detail 2: Controleer of de handtekening het hele document dekt.
                        if (!signatureUtil.SignatureCoversWholeDocument(name))
                        {
                            issues.Add("De handtekening dekt niet het volledige document. Dit kan betekenen dat er later niet-ondertekende content is toegevoegd.");
                        }

                        // Detail 3: Als de bovenstaande checks geen fout geven, is de integriteit zelf het probleem.
                        if (!issues.Any())
                        {
                            issues.Add("De cryptografische integriteit van de handtekening is verbroken. Dit duidt er meestal op dat het document is gewijzigd NADAT de handtekening is geplaatst.");
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
                return new AnalysisResult 
                { 
                    Level = AnalysisResult.SignatureLevel.SES, // Of een ander niveau, afhankelijk van hoe je dit wilt classificeren
                    Title = "Fout bij Analyse", 
                    Color = new SolidColorBrush(Colors.DarkRed), // Een duidelijke foutkleur
                    Explanation = $"Er is een onverwachte fout opgetreden tijdens de analyse van de PDF: {ex.Message}\n" +
                                  "Controleer of het bestand een geldige PDF is en niet beschadigd."
                };
            }
        }

        private AnalysisResult AnalyzeSingleSignature(PdfPKCS7 pkcs7, SignatureUtil signatureUtil, string signatureName, string signerName)
{
    try
    {
        IX509Certificate signingCert = pkcs7.GetSigningCertificate();
        bool isValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

                var (tsExists, tsValid, tsQualified, tsInfo) = AnalyzeTimestamp(pkcs7);
                
        if (isValid)
        {
            bool isQES = IsCertificateChainQualified(pkcs7);
            if (isQES)
            {
                        // Bereken de timestamp uitleg specifiek voor QES
                        string timestampExplanation = tsExists && tsValid
                            ? "\n\n✓ Deze handtekening bevat een geldige tijdstempel. Het tijdstip van ondertekening is cryptografisch beveiligd."
                            : "\n\n⚠ Deze handtekening bevat GEEN tijdstempel. De getoonde ondertekeningsdatum komt van de computer van de ondertekenaar en kan niet onafhankelijk worden geverifieerd.";

                return new AnalysisResult
                {
                    Level = AnalysisResult.SignatureLevel.QES,
                    Title = "Gekwalificeerde Handtekening (QES)",
                    Color = new SolidColorBrush(Colors.LightGreen),
                    SignerInfo = $"Ondertekend door: {signerName}",
                    TimestampInfo = tsInfo,  // NIEUW
                    HasQualifiedTimestamp = tsQualified,  // NIEUW
                    Explanation = "Deze handtekening is cryptografisch geldig én is geverifieerd tegen de officiële EU Trust List. Dit is een Gekwalificeerde Elektronische Handtekening (QES).\n\n" +
                                  "Wat betekent dit?\n" +
                                  "Een QES heeft dezelfde juridische status als een handgeschreven handtekening in de hele Europese Unie. Het biedt het hoogste niveau van zekerheid." +
                                  timestampExplanation  // NIEUW: voeg timestamp uitleg toe
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

                        // Bereken de timestamp uitleg specifiek voor AES
                        string timestampExplanation = tsExists && tsValid
                            ? "\n\n✓ Deze handtekening bevat een geldige tijdstempel."
                            : "\n\n⚠ Deze handtekening bevat GEEN tijdstempel.";

                        return new AnalysisResult
                {
                    Level = AnalysisResult.SignatureLevel.AES,
                    Title = "Geavanceerde Handtekening (AES)",
                    Color = new SolidColorBrush(Colors.DodgerBlue),
                    SignerInfo = $"Ondertekend door: {signerName}",
                    TimestampInfo = tsInfo,  // NIEUW
                    HasQualifiedTimestamp = tsQualified,  // NIEUW
                    Explanation = "Het document bevat een cryptografisch geldige handtekening. Dit wordt geclassificeerd als een Geavanceerde Elektronische Handtekening (AES).\n\n" +
                                  "Wat betekent dit?\n" +
                                  "De handtekening is geldig en het document is niet gewijzigd na ondertekening. Deze handtekening is echter niet geverifieerd tegen de EU Trust List en telt daarom niet als 'Gekwalificeerd'." +
                                  eutlWarning +
                                  timestampExplanation  // NIEUW: voeg timestamp uitleg toe
                };
            }
        }
        else
        {
            // De handtekening is cryptografisch ongeldig. Laten we de redenen verzamelen.
            var issues = new List<string>();

            // Detail 1: Controleer de geldigheid van het certificaat op de datum van ondertekening.
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

            // Detail 2: Controleer of de handtekening het hele document dekt.
            if (!signatureUtil.SignatureCoversWholeDocument(signatureName))
            {
                issues.Add("De handtekening dekt niet het volledige document. Dit kan betekenen dat er later niet-ondertekende content is toegevoegd.");
            }

            // Detail 3: Als de bovenstaande checks geen fout geven, is de integriteit zelf het probleem.
            if (!issues.Any())
            {
                issues.Add("De cryptografische integriteit van de handtekening is verbroken. Dit duidt er meestal op dat het document is gewijzigd NADAT de handtekening is geplaatst.");
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
    catch (Exception ex)
    {
        return new AnalysisResult
        {
            Level = AnalysisResult.SignatureLevel.SES,
            Title = "Fout bij Analyse",
            Color = new SolidColorBrush(Colors.DarkRed),
            Explanation = $"Er is een fout opgetreden tijdens de analyse van deze handtekening: {ex.Message}"
        };
    }
}

        private List<SignatureInfo> AnalyzeAllSignatures(string filePath)
        {
            var signatures = new List<SignatureInfo>();

            try
            {
                using (var pdfReader = new PdfReader(filePath))
                using (var pdfDoc = new PdfDocument(pdfReader))
                {
                    var signatureUtil = new SignatureUtil(pdfDoc);
                    var signatureNames = signatureUtil.GetSignatureNames();

                    int index = 1;
                    foreach (var name in signatureNames)
                    {
                        var sigInfo = new SignatureInfo
                        {
                            Index = index++,
                            SignatureName = name
                        };

                        try
                        {
                            PdfPKCS7 pkcs7 = signatureUtil.ReadSignatureData(name);
                            IX509Certificate signingCert = pkcs7.GetSigningCertificate();

                            sigInfo.SignerName = CertificateInfo.GetSubjectFields(signingCert)?.GetField("CN") ?? "Onbekend";
                            sigInfo.SignDate = pkcs7.GetSignDate().ToString("dd-MM-yyyy HH:mm");

                            // Voer volledige analyse uit voor deze handtekening
                            sigInfo.FullAnalysis = AnalyzeSingleSignature(pkcs7, signatureUtil, name, sigInfo.SignerName);

                            // Bepaal de status voor de lijst
                            sigInfo.Status = sigInfo.FullAnalysis.Level switch
                            {
                                AnalysisResult.SignatureLevel.QES => "QES ✓",
                                AnalysisResult.SignatureLevel.AES => "AES ✓",
                                _ => sigInfo.FullAnalysis.Title.Contains("ONGELDIG") ? "Ongeldig ✗" : "SES"
                            };
                        }
                        catch (Exception ex)
                        {
                            sigInfo.SignerName = "Fout bij lezen";
                            sigInfo.Status = "Onleesbaar";
                            sigInfo.FullAnalysis = new AnalysisResult
                            {
                                Title = "Fout bij Analyse",
                                Color = new SolidColorBrush(Colors.DarkRed),
                                Explanation = $"Kon handtekening niet lezen: {ex.Message}"
                            };
                        }

                        signatures.Add(sigInfo);
                    }
                }
            }
            catch (Exception ex)
            {
                // Fout bij openen PDF
            }

            return signatures;
        }

        private void SignatureListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SignatureListBox.SelectedItem is SignatureInfo selected)
            {
                // Use the REAL file path for the viewer
                UpdateUIWithResult(selected.FullAnalysis, _currentFilePath);

                // If you still want to show which signature is selected, update a separate label:
                ResultFilename.Text =
                    $"Bestand: {System.IO.Path.GetFileName(_currentFilePath)}\n" +
                    $"Handtekening {selected.Index}: {selected.SignerName}\n" +
                    $"{selected.FullAnalysis.SignerInfo}";
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
                var certChainFromPdf = pkcs7.GetSignCertificateChain()
                    .Select(c => parser.ReadCertificate(c.GetEncoded()))
                    .ToList();

                if (!certChainFromPdf.Any())
                {
                    return false;
                }

                // --- DE NIEUWE, SNELLE CRL-CHECK ---
                // Controleer elk certificaat in de keten tegen de 'Master Zwarte Lijst'.
                foreach (var certInChain in certChainFromPdf)
                {
                    if (_eutlService.RevokedSerialNumbers.Contains(certInChain.SerialNumber.ToString()))
                    {
                        // GEVONDEN OP ZWARTE LIJST! De hele keten is per definitie ongeldig.
                        return false;
                    }
                }
                // --- EINDE CRL-CHECK ---

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
                        catch { return false; }
                    }
                }
                return false;
            }
            catch { return false; }
        }

        private void UpdateUIWithResult(AnalysisResult result, string filePath)
        {
            ResultPanel.BorderBrush = result.Color;
            ResultTitle.Text = result.Title;
            ResultTitle.Foreground = result.Color;
            // Keep showing the actual file name here
            ResultFilename.Text = $"Bestand: {System.IO.Path.GetFileName(filePath)}\n{result.SignerInfo}";
            ResultExplanation.Text = result.Explanation;
            ResultPanel.Visibility = Visibility.Visible;

            // Always navigate using the REAL path
            PdfWebView.Source = new Uri(new Uri(filePath).AbsoluteUri);
        }

        private void SetButtonMainText(string text, bool showDragHint = true)
        {
            if (SelectPdfButtonText.Inlines.FirstOrDefault() is Run firstRun)
            {
                firstRun.Text = text;
            }

            // Show or hide the drag-and-drop hint by setting/clearing the text
            if (SelectPdfButtonHint != null)
            {
                SelectPdfButtonHint.Text = showDragHint ? "of sleep een PDF bestand hierheen" : "";
            }
        }

        private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Application.Current.Shutdown(); // Gebruik de volledige kwalificatie
        
        }

        private void OnlineHelpMenuItem_Click(object sender, RoutedEventArgs e)
        {
            // Voorbeeld: Open een URL in de standaardbrowser
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://www.jouwwebsite.nl/help", // Vervang dit met je eigen help-URL
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Kan help-pagina niet openen: {ex.Message}", "Fout", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        

        private (bool exists, bool isValid, bool isQualified, string info) AnalyzeTimestamp(PdfPKCS7 pkcs7)
        {
            try
            {
                // Stap 1: Controleer of er een timestamp bestaat
                DateTime? timestampDate = pkcs7.GetTimeStampDate();

                if (!timestampDate.HasValue)
                {
                    return (false, false, false, "Geen tijdstempel aanwezig");
                }

                // Stap 2: Verifieer de timestamp
                bool isTimestampValid = false;
                try
                {
                    isTimestampValid = pkcs7.VerifyTimestampImprint();
                }
                catch (Exception ex)
                {
                    return (true, false, false, $"Tijdstempel gevonden maar validatie mislukt: {ex.Message}");
                }

                if (!isTimestampValid)
                {
                    return (true, false, false, $"Tijdstempel aanwezig ({timestampDate:dd-MM-yyyy HH:mm}) maar is ONGELDIG");
                }

                // Stap 3: Timestamp is geldig
                // We kunnen niet betrouwbaar het TSA certificaat verkrijgen, dus we tonen alleen dat er een geldige timestamp is
                string info = $"✓ Geldige tijdstempel: {timestampDate:dd-MM-yyyy HH:mm:ss} UTC";

                // Als de EUTL beschikbaar is, vermelden we dat we niet kunnen verifiëren of het gekwalificeerd is
                if (_eutlService.TrustedCertificates != null && _eutlService.TrustedCertificates.Any())
                {
                    info += "\n(Verificatie tegen EU Trust List: niet ondersteund voor timestamps)";
                }

                return (true, true, false, info); // exists=true, valid=true, qualified=false (kunnen we niet bepalen)
            }
            catch (Exception ex)
            {
                return (false, false, false, $"Fout bij timestamp analyse: {ex.Message}");
            }
        }

        private void CopyLog_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(LogTextBox.Text);
        }


        // NIEUW TOE TE VOEGEN BLOK: Event handlers voor drag-and-drop op het linkerpaneel
        private void LeftPanelDropTarget_DragEnter(object sender, DragEventArgs e)
        {
            // Zorg dat de LeftPanelDropTarget zichtbaar wordt (als vangnet)
            LeftPanelDropTarget.Visibility = Visibility.Visible;
            e.Effects = DragDropEffects.None; // Start met 'verboden' cursor
            e.Handled = true;
        }

        private void LeftPanelDropTarget_DragOver(object sender, DragEventArgs e)
        {
            bool isPdf = e.Data.GetDataPresent(DataFormats.FileDrop) &&
                         ((string[])e.Data.GetData(DataFormats.FileDrop))
                         .Any(f => f.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase));

            if (isPdf)
            {
                e.Effects = DragDropEffects.Copy;
                //DragDropOverlay.Visibility = Visibility.Visible; // Toon de blauwe overlay
            }
            else
            {
                e.Effects = DragDropEffects.None;
                //DragDropOverlay.Visibility = Visibility.Collapsed; // Verberg de overlay als het geen PDF is
            }
            e.Handled = true;
        }

        private void LeftPanelDropTarget_DragLeave(object sender, DragEventArgs e)
        {
            // Verberg zowel de overlay als het vangnet
            //DragDropOverlay.Visibility = Visibility.Collapsed;
            LeftPanelDropTarget.Visibility = Visibility.Collapsed;
            e.Handled = true;
        }

        private void LeftPanelDropTarget_Drop(object sender, DragEventArgs e)
        {
            // Verberg zowel de overlay als het vangnet
            //DragDropOverlay.Visibility = Visibility.Collapsed;
            LeftPanelDropTarget.Visibility = Visibility.Collapsed;

            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                var pdfFile = files.FirstOrDefault(f => f.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase));
                if (pdfFile != null)
                {
                    StartAnalysis(pdfFile);
                }
            }
            e.Handled = true;
        }
    }
}
using iText.Commons.Bouncycastle.Cert;
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
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using ComTypes = System.Runtime.InteropServices.ComTypes;

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
        #region COM Structures and Interfaces for Email Attachments

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FILEDESCRIPTOR
        {
            public uint dwFlags;
            public Guid clsid;
            public System.Drawing.Size sizel;
            public System.Drawing.Point pointl;
            public uint dwFileAttributes;
            public ComTypes.FILETIME ftCreationTime;
            public ComTypes.FILETIME ftLastAccessTime;
            public ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
        }

        [ComImport]
        [Guid("0000000C-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IStream
        {
            void Read([Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, int cb, IntPtr pcbRead);
            void Write([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, int cb, IntPtr pcbWritten);
            void Seek(long dlibMove, int dwOrigin, IntPtr plibNewPosition);
            void SetSize(long libNewSize);
            void CopyTo(IStream pstm, long cb, IntPtr pcbRead, IntPtr pcbWritten);
            void Commit(int grfCommitFlags);
            void Revert();
            void LockRegion(long libOffset, long cb, int dwLockType);
            void UnlockRegion(long libOffset, long cb, int dwLockType);
            void Stat(out ComTypes.STATSTG pstatstg, int grfStatFlag);
            void Clone(out IStream ppstm);
        }

        [DllImport("ole32.dll")]
        private static extern void ReleaseStgMedium(ref ComTypes.STGMEDIUM pmedium);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern int GlobalSize(IntPtr hMem);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern ushort RegisterClipboardFormat(string lpszFormat);

        #endregion

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
            aboutWindow.ShowDialog();
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

            string initialStatus = _eutlService.LoadFromCache();
            UpdateLog(initialStatus);

            var cacheMaxAge = TimeSpan.FromDays(7);
            bool isCacheMissing = !_eutlService.TrustedCertificates.Any();
            bool isCacheOld = (DateTime.UtcNow - _eutlService.LastUpdated) > cacheMaxAge;

            if (isCacheMissing || isCacheOld)
            {
                string reason = isCacheMissing ? "Geen cache gevonden" : "Cache is verouderd";
                UpdateLog(LogTextBox.Text + $" ({reason}, bezig met downloaden...)");

                Action<string> downloadCallback = (status) => Dispatcher.Invoke(() => SetButtonMainText(status, false));
                string updateStatus = await _eutlService.UpdateTrustListAsync(downloadCallback);

                UpdateLog(updateStatus);
            }
            else if (_eutlService.HashNeedsUpdate(cacheMaxAge))
            {
                UpdateLog(LogTextBox.Text + " Hash is verouderd, opnieuw bouwen...");
                SetButtonMainText("Hash Bouwen...", false);

                await Task.Run(() => _eutlService.RebuildHashFromCache());

                UpdateLog($"EU lijsten geladen uit cache ({_eutlService.TrustedCertificates.Count} certs, {_eutlService.RevokedSerialNumbers.Count} ingetrokken serienummers). Hash bijgewerkt op {_eutlService.HashLastUpdated:dd-MM-yyyy HH:mm} UTC.");
            }
            else
            {
                UpdateLog($"EU lijsten geladen uit cache ({_eutlService.TrustedCertificates.Count} certs, {_eutlService.RevokedSerialNumbers.Count} ingetrokken serienummers). Laatst bijgewerkt: {_eutlService.LastUpdated:dd-MM-yyyy HH:mm} UTC.");
            }

            SelectPdfButton.IsEnabled = true;
            SetButtonMainText("Selecteer en Analyseer PDF", true);
        }

        private void SelectPdfButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog { Filter = "PDF Files|*.pdf", Title = "Selecteer een PDF-bestand" };

            if (openFileDialog.ShowDialog() == true)
            {
                StartAnalysis(openFileDialog.FileName);
            }
        }

        private void StartAnalysis(string filePath)
        {
            _currentFilePath = filePath;

            ResultPanel.Visibility = Visibility.Collapsed;
            SelectPdfButton.IsEnabled = false;
            SetButtonMainText("Analyse Bezig...", false);

            if (File.Exists(filePath))
            {
                PdfWebView.Source = new Uri($"file:///{filePath}");
            }

            Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Background);

            _allSignatures = AnalyzeAllSignatures(filePath);

            if (_allSignatures.Any())
            {
                SignatureListPanel.Visibility = Visibility.Visible;
                SignatureListBox.ItemsSource = _allSignatures;
                SignatureListBox.SelectedIndex = 0;
            }
            else
            {
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
                        string timestampExplanation = tsExists && tsValid
                            ? "\n\n✓ Deze handtekening bevat een geldige tijdstempel. Het tijdstip van ondertekening is cryptografisch beveiligd."
                            : "\n\n⚠ Deze handtekening bevat GEEN tijdstempel. De getoonde ondertekeningsdatum komt van de computer van de ondertekenaar en kan niet onafhankelijk worden geverifieerd.";

                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.QES,
                            Title = "Gekwalificeerde Handtekening (QES)",
                            Color = new SolidColorBrush(Colors.LightGreen),
                            SignerInfo = $"Ondertekend door: {signerName}",
                            TimestampInfo = tsInfo,
                            HasQualifiedTimestamp = tsQualified,
                            Explanation = "Deze handtekening is cryptografisch geldig én is geverifieerd tegen de officiële EU Trust List. Dit is een Gekwalificeerde Elektronische Handtekening (QES).\n\n" +
                                          "Wat betekent dit?\n" +
                                          "Een QES heeft dezelfde juridische status als een handgeschreven handtekening in de hele Europese Unie. Het biedt het hoogste niveau van zekerheid." +
                                          timestampExplanation
                        };
                    }
                    else
                    {
                        string eutlWarning = string.Empty;
                        if (!_eutlService.TrustedCertificates.Any())
                        {
                            eutlWarning = "\n\nWAARSCHUWING: De EU Trust List kon niet worden geladen. Deze handtekening kon daarom niet op QES-status worden gecontroleerd en wordt als AES weergegeven.";
                        }

                        string timestampExplanation = tsExists && tsValid
                            ? "\n\n✓ Deze handtekening bevat een geldige tijdstempel."
                            : "\n\n⚠ Deze handtekening bevat GEEN tijdstempel.";

                        return new AnalysisResult
                        {
                            Level = AnalysisResult.SignatureLevel.AES,
                            Title = "Geavanceerde Handtekening (AES)",
                            Color = new SolidColorBrush(Colors.DodgerBlue),
                            SignerInfo = $"Ondertekend door: {signerName}",
                            TimestampInfo = tsInfo,
                            HasQualifiedTimestamp = tsQualified,
                            Explanation = "Het document bevat een cryptografisch geldige handtekening. Dit wordt geclassificeerd als een Geavanceerde Elektronische Handtekening (AES).\n\n" +
                                          "Wat betekent dit?\n" +
                                          "De handtekening is geldig en het document is niet gewijzigd na ondertekening. Deze handtekening is echter niet geverifieerd tegen de EU Trust List en telt daarom niet als 'Gekwalificeerd'." +
                                          eutlWarning +
                                          timestampExplanation
                        };
                    }
                }
                else
                {
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

                    if (!signatureUtil.SignatureCoversWholeDocument(signatureName))
                    {
                        issues.Add("De handtekening dekt niet het volledige document. Dit kan betekenen dat er later niet-ondertekende content is toegevoegd.");
                    }

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

                            sigInfo.FullAnalysis = AnalyzeSingleSignature(pkcs7, signatureUtil, name, sigInfo.SignerName);

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
                UpdateUIWithResult(selected.FullAnalysis, _currentFilePath);

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

                foreach (var certInChain in certChainFromPdf)
                {
                    if (_eutlService.RevokedSerialNumbers.Contains(certInChain.SerialNumber.ToString()))
                    {
                        return false;
                    }
                }

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
            ResultFilename.Text = $"Bestand: {System.IO.Path.GetFileName(filePath)}\n{result.SignerInfo}";
            ResultExplanation.Text = result.Explanation;
            ResultPanel.Visibility = Visibility.Visible;

            PdfWebView.Source = new Uri(new Uri(filePath).AbsoluteUri);
        }

        private void SetButtonMainText(string text, bool showDragHint = true)
        {
            if (SelectPdfButtonText.Inlines.FirstOrDefault() is Run firstRun)
            {
                firstRun.Text = text;
            }

            if (SelectPdfButtonHint != null)
            {
                SelectPdfButtonHint.Text = showDragHint ? "of sleep een PDF bestand hierheen" : "";
            }
        }

        private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Application.Current.Shutdown();
        }

        private void OnlineHelpMenuItem_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://www.jouwwebsite.nl/help",
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
                DateTime? timestampDate = pkcs7.GetTimeStampDate();

                if (!timestampDate.HasValue)
                {
                    return (false, false, false, "Geen tijdstempel aanwezig");
                }

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

                string info = $"✓ Geldige tijdstempel: {timestampDate:dd-MM-yyyy HH:mm:ss} UTC";

                if (_eutlService.TrustedCertificates != null && _eutlService.TrustedCertificates.Any())
                {
                    info += "\n(Verificatie tegen EU Trust List: niet ondersteund voor timestamps)";
                }

                return (true, true, false, info);
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

        #region Drag and Drop Event Handlers - UITGEBREID

        private void LeftPanelDropTarget_DragEnter(object sender, DragEventArgs e)
        {
            LeftPanelDropTarget.Visibility = Visibility.Visible;

            if (IsValidDrop(e.Data))
            {
                e.Effects = DragDropEffects.Copy;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void LeftPanelDropTarget_DragOver(object sender, DragEventArgs e)
        {
            if (IsValidDrop(e.Data))
            {
                e.Effects = DragDropEffects.Copy;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void LeftPanelDropTarget_DragLeave(object sender, DragEventArgs e)
        {
            LeftPanelDropTarget.Visibility = Visibility.Collapsed;
            e.Handled = true;
        }

        private async void LeftPanelDropTarget_Drop(object sender, DragEventArgs e)
        {
            LeftPanelDropTarget.Visibility = Visibility.Collapsed;

            string filePath = null;

            // Prioriteit 1: Outlook/Email bijlagen (FileGroupDescriptor formaat)
            if (e.Data.GetDataPresent("FileGroupDescriptorW") || e.Data.GetDataPresent("FileGroupDescriptor"))
            {
                filePath = await HandleOutlookAttachment(e.Data);
            }
            // Prioriteit 2: Standaard bestand drop vanuit Windows Verkenner
            else if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                try
                {
                    string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                    if (files != null && files.Length > 0)
                    {
                        filePath = files.FirstOrDefault(f => f.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase));
                    }
                }
                catch (COMException)
                {
                    // FileDrop mislukt, probeer virtuele bestand benadering
                    filePath = await HandleOutlookAttachment(e.Data);
                }
            }
            // Prioriteit 3: Web-gebaseerde email (probeer te extraheren, anders toon instructies)
            else
            {
                filePath = await HandleWebBasedEmail(e.Data);
            }

            // Verwerk het bestand als het succesvol is geëxtraheerd
            if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
            {
                StartAnalysis(filePath);
            }

            e.Handled = true;
        }

        #endregion

        #region Email Attachment Helper Methods

        /// <summary>
        /// Controleert of de drag data geldige bestandsformaten bevat
        /// </summary>
        private bool IsValidDrop(System.Windows.IDataObject data)
        {
            return data.GetDataPresent(DataFormats.FileDrop) ||
                   data.GetDataPresent("FileGroupDescriptorW") ||
                   data.GetDataPresent("FileGroupDescriptor") ||
                   data.GetDataPresent("FileNameW") ||
                   data.GetDataPresent("FileName");
        }

        /// <summary>
        /// Verwerkt Outlook desktop bijlagen met FileGroupDescriptor formaat
        /// </summary>
        private async Task<string> HandleOutlookAttachment(System.Windows.IDataObject data)
        {
            try
            {
                string descriptorFormat = data.GetDataPresent("FileGroupDescriptorW")
                    ? "FileGroupDescriptorW"
                    : "FileGroupDescriptor";

                MemoryStream descriptorStream = (MemoryStream)data.GetData(descriptorFormat);
                if (descriptorStream == null || descriptorStream.Length < 4)
                    return null;

                byte[] descriptorBytes = descriptorStream.ToArray();
                int fileCount = BitConverter.ToInt32(descriptorBytes, 0);

                if (fileCount > 0)
                {
                    int structSize = Marshal.SizeOf(typeof(FILEDESCRIPTOR));
                    if (4 + structSize > descriptorBytes.Length)
                        return null;

                    IntPtr ptr = Marshal.AllocHGlobal(structSize);
                    try
                    {
                        Marshal.Copy(descriptorBytes, 4, ptr, structSize);
                        FILEDESCRIPTOR fileDescriptor = Marshal.PtrToStructure<FILEDESCRIPTOR>(ptr);

                        string fileName = fileDescriptor.cFileName;
                        fileName = Path.GetInvalidFileNameChars()
                            .Aggregate(fileName, (current, c) => current.Replace(c.ToString(), "_"));

                        // Alleen PDF bestanden verwerken
                        if (!fileName.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
                            return null;

                        // Verkrijg bestandsinhoud
                        ComTypes.IDataObject comData = data as ComTypes.IDataObject;
                        if (comData == null)
                            return null;

                        MemoryStream fileContentStream = GetFileContents(comData, 0);
                        if (fileContentStream != null && fileContentStream.Length > 0)
                        {
                            string tempPath = GetUniqueTempPath(fileName);
                            await SaveStreamToFileAsync(fileContentStream, tempPath);
                            return tempPath;
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                }
            }
            catch
            {
                // Mislukt om te extraheren, return null
            }

            return null;
        }

        /// <summary>
        /// Verwerkt web-gebaseerde email clients - toont Nederlandse instructies als bestand niet toegankelijk is
        /// </summary>
        private async Task<string> HandleWebBasedEmail(System.Windows.IDataObject data)
        {
            try
            {
                ComTypes.IDataObject comData = data as ComTypes.IDataObject;
                if (comData == null)
                    return null;

                // Probeer alle beschikbare formaten voor daadwerkelijke PDF inhoud
                string[] allFormats = data.GetFormats();

                foreach (string formatName in allFormats)
                {
                    // Sla bekende metadata-only formaten over
                    if (IsMetadataFormat(formatName))
                        continue;

                    try
                    {
                        MemoryStream contentStream = TryGetStreamFromFormat(comData, formatName);

                        if (contentStream != null && contentStream.Length > 0)
                        {
                            // Controleer of dit een geldige PDF is
                            if (await IsValidPdfStream(contentStream))
                            {
                                string tempPath = GetUniqueTempPath("email_bijlage.pdf");
                                await SaveStreamToFileAsync(contentStream, tempPath);
                                return tempPath;
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                // Geen daadwerkelijk bestand gevonden - toon Nederlandse instructies
                ShowDutchSaveInstructions();
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Toont Nederlandse melding waarin gebruiker wordt gevraagd bijlage eerst op te slaan
        /// </summary>
        private void ShowDutchSaveInstructions()
        {
            MessageBox.Show(
                "De e-mailclient biedt geen directe toegang tot de bijlage.\n\n" +
                "1 Sla het PDF bestand op in een lokale folder'\n" +
                "2. Sleep het opgeslagen bestand vanuit uw\n" +
                "   Downloads-map naar dit venster\n\n" +
                "Het bestand wordt dan automatisch verwerkt.",
                "Bijlage eerst opslaan",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        /// <summary>
        /// Verkrijgt FileContents van COM IDataObject met specifieke index
        /// </summary>
        private MemoryStream GetFileContents(ComTypes.IDataObject comData, int index)
        {
            try
            {
                ushort cfFileContents = RegisterClipboardFormat("FileContents");

                ComTypes.FORMATETC formatetc = new ComTypes.FORMATETC
                {
                    cfFormat = (short)cfFileContents,
                    dwAspect = ComTypes.DVASPECT.DVASPECT_CONTENT,
                    lindex = index,
                    tymed = ComTypes.TYMED.TYMED_ISTREAM | ComTypes.TYMED.TYMED_HGLOBAL,
                    ptd = IntPtr.Zero
                };

                ComTypes.STGMEDIUM medium = new ComTypes.STGMEDIUM();
                comData.GetData(ref formatetc, out medium);

                try
                {
                    // Probeer eerst IStream
                    if ((medium.tymed & ComTypes.TYMED.TYMED_ISTREAM) != 0)
                    {
                        IStream istream = Marshal.GetObjectForIUnknown(medium.unionmember) as IStream;
                        if (istream != null)
                        {
                            ComTypes.STATSTG statstg;
                            istream.Stat(out statstg, 0);

                            byte[] buffer = new byte[statstg.cbSize];
                            IntPtr bytesReadPtr = Marshal.AllocHGlobal(sizeof(int));
                            try
                            {
                                istream.Read(buffer, (int)statstg.cbSize, bytesReadPtr);
                                int bytesRead = Marshal.ReadInt32(bytesReadPtr);
                                return new MemoryStream(buffer, 0, bytesRead);
                            }
                            finally
                            {
                                Marshal.FreeHGlobal(bytesReadPtr);
                            }
                        }
                    }
                    // Probeer HGLOBAL
                    else if ((medium.tymed & ComTypes.TYMED.TYMED_HGLOBAL) != 0 && medium.unionmember != IntPtr.Zero)
                    {
                        IntPtr ptr = GlobalLock(medium.unionmember);
                        try
                        {
                            int size = GlobalSize(medium.unionmember);
                            if (size > 0)
                            {
                                byte[] buffer = new byte[size];
                                Marshal.Copy(ptr, buffer, 0, size);
                                return new MemoryStream(buffer);
                            }
                        }
                        finally
                        {
                            GlobalUnlock(medium.unionmember);
                        }
                    }
                }
                finally
                {
                    ReleaseStgMedium(ref medium);
                }
            }
            catch
            {
                // Stil falen
            }

            return null;
        }

        /// <summary>
        /// Probeert stream te verkrijgen van specifiek clipboard formaat
        /// </summary>
        private MemoryStream TryGetStreamFromFormat(ComTypes.IDataObject comData, string formatName)
        {
            try
            {
                ushort cfFormat = RegisterClipboardFormat(formatName);

                ComTypes.FORMATETC formatetc = new ComTypes.FORMATETC
                {
                    cfFormat = (short)cfFormat,
                    dwAspect = ComTypes.DVASPECT.DVASPECT_CONTENT,
                    lindex = -1,
                    tymed = ComTypes.TYMED.TYMED_ISTREAM | ComTypes.TYMED.TYMED_HGLOBAL,
                    ptd = IntPtr.Zero
                };

                ComTypes.STGMEDIUM medium = new ComTypes.STGMEDIUM();
                comData.GetData(ref formatetc, out medium);

                try
                {
                    if ((medium.tymed & ComTypes.TYMED.TYMED_ISTREAM) != 0)
                    {
                        IStream istream = Marshal.GetObjectForIUnknown(medium.unionmember) as IStream;
                        if (istream != null)
                        {
                            ComTypes.STATSTG statstg;
                            istream.Stat(out statstg, 0);

                            byte[] buffer = new byte[statstg.cbSize];
                            IntPtr bytesReadPtr = Marshal.AllocHGlobal(sizeof(int));
                            try
                            {
                                istream.Read(buffer, (int)statstg.cbSize, bytesReadPtr);
                                int bytesRead = Marshal.ReadInt32(bytesReadPtr);
                                return new MemoryStream(buffer, 0, bytesRead);
                            }
                            finally
                            {
                                Marshal.FreeHGlobal(bytesReadPtr);
                            }
                        }
                    }
                    else if ((medium.tymed & ComTypes.TYMED.TYMED_HGLOBAL) != 0 && medium.unionmember != IntPtr.Zero)
                    {
                        IntPtr ptr = GlobalLock(medium.unionmember);
                        try
                        {
                            int size = GlobalSize(medium.unionmember);
                            if (size > 0)
                            {
                                byte[] buffer = new byte[size];
                                Marshal.Copy(ptr, buffer, 0, size);
                                return new MemoryStream(buffer);
                            }
                        }
                        finally
                        {
                            GlobalUnlock(medium.unionmember);
                        }
                    }
                }
                finally
                {
                    ReleaseStgMedium(ref medium);
                }
            }
            catch
            {
                // Formaat niet beschikbaar
            }

            return null;
        }

        /// <summary>
        /// Controleert of formaatname alleen metadata is (geen daadwerkelijke bestandsinhoud)
        /// </summary>
        private bool IsMetadataFormat(string formatName)
        {
            return formatName == "DragContext" ||
                   formatName == "DragImageBits" ||
                   formatName == "InShellDragLoop" ||
                   formatName == "Preferred DropEffect" ||
                   formatName == "Shell Object Offsets" ||
                   formatName == "chromium/x-renderer-taint" ||
                   formatName == "FileName" ||
                   formatName == "FileNameW";
        }

        /// <summary>
        /// Valideert of stream een geldig PDF bestand bevat
        /// </summary>
        private async Task<bool> IsValidPdfStream(MemoryStream stream)
        {
            try
            {
                if (stream.Length < 5)
                    return false;

                long originalPosition = stream.Position;
                stream.Position = 0;

                byte[] header = new byte[5];
                await stream.ReadAsync(header, 0, 5);

                stream.Position = originalPosition;

                // PDF bestanden beginnen met "%PDF-"
                return header[0] == 0x25 && // %
                       header[1] == 0x50 && // P
                       header[2] == 0x44 && // D
                       header[3] == 0x46 && // F
                       header[4] == 0x2D;   // -
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Verkrijgt uniek tijdelijk bestandspad
        /// </summary>
        private string GetUniqueTempPath(string fileName)
        {
            fileName = Path.GetInvalidFileNameChars()
                .Aggregate(fileName, (current, c) => current.Replace(c.ToString(), "_"));

            string tempPath = Path.Combine(Path.GetTempPath(), fileName);
            int counter = 0;
            string originalTempPath = tempPath;

            while (File.Exists(tempPath))
            {
                counter++;
                tempPath = Path.Combine(
                    Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(originalTempPath) +
                    $"_{counter}" +
                    Path.GetExtension(originalTempPath));
            }

            return tempPath;
        }

        /// <summary>
        /// Slaat stream asynchroon op naar bestand
        /// </summary>
        private async Task SaveStreamToFileAsync(Stream stream, string filePath)
        {
            using (FileStream fileStream = new FileStream(
                filePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                4096,
                useAsync: true))
            {
                stream.Position = 0;
                await stream.CopyToAsync(fileStream);
            }
        }

        #endregion
    }
}
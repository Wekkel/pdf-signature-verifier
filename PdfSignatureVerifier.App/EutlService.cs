using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using iText.Commons.Bouncycastle.Cert;
using Org.BouncyCastle.X509;

namespace PdfSignatureVerifier.App
{
    public class EutlService
    {
        private const string EU_LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
        private readonly string _cacheFilePath;

        public List<X509Certificate> TrustedCertificates { get; private set; } = new List<X509Certificate>();
        public DateTime LastUpdated { get; private set; }

        public EutlService()
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string appFolder = Path.Combine(appDataPath, "PdfSignatureVerifier");
            Directory.CreateDirectory(appFolder);
            _cacheFilePath = Path.Combine(appFolder, "eutl-cache.json");
        }

        public string LoadFromCache()
        {
            try
            {
                if (File.Exists(_cacheFilePath))
                {
                    var cacheJson = File.ReadAllText(_cacheFilePath);
                    var cacheData = JsonSerializer.Deserialize<CacheData>(cacheJson);
                    if (cacheData?.Base64Certificates == null) return "Cache is corrupt.";

                    var parser = new X509CertificateParser();
                    TrustedCertificates = cacheData.Base64Certificates
     .Select(b64 => parser.ReadCertificate(Convert.FromBase64String(b64)))
     .ToList();
                    LastUpdated = cacheData.LastUpdated;
                    return $"EU Trust List geladen uit cache ({TrustedCertificates.Count} certificaten). Laatst bijgewerkt: {LastUpdated:dd-MM-yyyy HH:mm} UTC.";
                }
                return "Geen lokale EU Trust List cache gevonden.";
            }
            catch (Exception ex)
            {
                return $"Fout bij laden cache: {ex.Message}";
            }
        }

        public async Task<string> UpdateTrustListAsync()
        {
            string debugXmlFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PdfSignatureVerifier", "Debug_XML");
            Directory.CreateDirectory(debugXmlFolder);

            try
            {
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PdfSignatureVerifier/1.0 (Windows; .NET)");

                    string lotlXmlString;
                    try
                    {
                        lotlXmlString = await httpClient.GetStringAsync(EU_LOTL_URL);
                        File.WriteAllText(Path.Combine(debugXmlFolder, "00_EU_LOTL_SUCCESS.xml"), lotlXmlString);
                    }
                    catch (HttpRequestException netEx)
                    {
                        File.WriteAllText(Path.Combine(debugXmlFolder, "00_EU_LOTL_ERROR.txt"), netEx.ToString());
                        return $"Update mislukt: kon de EU hoofdlijst niet downloaden. Details: {netEx.Message}";
                    }

                    var lotlXml = XDocument.Parse(lotlXmlString);

                    // --- DE DEFINITIEVE, CORRECTE PARSER VOOR DE HOOFDLIJST ---
                    // We definiëren de namespace die in de XML wordt gebruikt.
                    XNamespace ns = "http://uri.etsi.org/02231/v2#";

                    // We volgen nu de correcte hiërarchie:
                    // TrustServiceStatusList -> SchemeInformation -> PointersToOtherTSL -> OtherTSLPointer -> TSLLocation
                    var tslUrls = lotlXml.Root
                                         .Element(ns + "SchemeInformation")?
                                         .Element(ns + "PointersToOtherTSL")?
                                         .Elements(ns + "OtherTSLPointer")
                                         .Select(pointer => pointer.Element(ns + "TSLLocation")?.Value)
                                         .Where(url => !string.IsNullOrEmpty(url))
                                         .ToList();

                    if (tslUrls == null || !tslUrls.Any())
                    {
                        // Deze fout zou nu opgelost moeten zijn.
                        return "Update mislukt: geen links naar land-specifieke lijsten gevonden in de hoofdlijst (parser-fout).";
                    }

                    var allCerts = new List<X509Certificate>();
                    var parser = new X509CertificateParser();

                    foreach (var url in tslUrls)
                    {
                        // --- DE CRUCIALE VEILIGHEIDSCHECK ---
                        if (!url.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                        {
                            // Sla bestanden over die geen XML zijn (zoals PDFs)
                            continue;
                        }

                        string fileName = Path.GetFileName(new Uri(url).AbsolutePath);
                        if (string.IsNullOrEmpty(fileName))
                        {
                            fileName = Guid.NewGuid().ToString() + ".xml";
                        }

                        try
                        {
                            var tslXmlString = await httpClient.GetStringAsync(url);
                            File.WriteAllText(Path.Combine(debugXmlFolder, fileName), tslXmlString);

                            var tslXml = XDocument.Parse(tslXmlString);
                            var base64Certs = tslXml.Descendants()
                                                .Where(e => e.Name.LocalName == "X509Certificate")
                                                .Select(c => c.Value.Trim());

                            foreach (var base64Cert in base64Certs)
                            {
                                if (string.IsNullOrWhiteSpace(base64Cert)) continue;
                                var certBytes = Convert.FromBase64String(base64Cert);
                                var certsInStream = parser.ReadCertificates(new MemoryStream(certBytes));
                                allCerts.AddRange(certsInStream.Cast<X509Certificate>());
                            }
                        }
                        catch (HttpRequestException netEx)
                        {
                            File.WriteAllText(Path.Combine(debugXmlFolder, $"{fileName}.error.txt"), netEx.ToString());
                        }
                        catch (Exception parseEx)
                        {
                            // Vang ook parse-fouten op voor het geval een .xml-bestand corrupt is
                            File.WriteAllText(Path.Combine(debugXmlFolder, $"{fileName}.parse-error.txt"), parseEx.ToString());
                        }
                    }

                    if (allCerts.Any())
                    {
                        TrustedCertificates = allCerts.DistinctBy(c => c.GetHashCode()).ToList();
                        LastUpdated = DateTime.UtcNow;
                        SaveToCache();
                        return $"EU Trust List succesvol bijgewerkt ({TrustedCertificates.Count} certificaten).";
                    }
                    return $"Update voltooid, maar geen certificaten gevonden in de EU-lijsten. Controleer de XML-bestanden in de Debug_XML map.";
                }
            }
            catch (Exception ex)
            {
                string errorLogPath = Path.Combine(debugXmlFolder, "FATAL_ERROR.txt");
                File.WriteAllText(errorLogPath, ex.ToString());
                return $"Een onverwachte fout is opgetreden: {ex.Message}. Controleer de log in {errorLogPath}";
            }
        }

        private void SaveToCache()
        {
            var cacheData = new CacheData
            {
                LastUpdated = this.LastUpdated,
                Base64Certificates = TrustedCertificates.Select(c => Convert.ToBase64String(c.GetEncoded())).ToList()
            };
            var cacheJson = JsonSerializer.Serialize(cacheData);
            File.WriteAllText(_cacheFilePath, cacheJson);
        }

        private class CacheData
        {
            public DateTime LastUpdated { get; set; }
            public List<string> Base64Certificates { get; set; }
        }
    }
}
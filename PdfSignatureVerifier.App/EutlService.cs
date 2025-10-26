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
    // Aparte class voor onze cache, nu met een plek voor CRLs
    public class EutlCacheData
    {
        public DateTime LastUpdated { get; set; }
        public List<string> TrustedCertificatesB64 { get; set; }
        public Dictionary<string, string> CrlsB64 { get; set; } // Key = URL, Value = Base64 CRL data
    }

    public class EutlService
    {
        private const string EU_LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
        private readonly string _cacheFilePath;

        public List<X509Certificate> TrustedCertificates { get; private set; } = new List<X509Certificate>();
        public Dictionary<string, byte[]> CrlCache { get; private set; } = new Dictionary<string, byte[]>();
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
                    var cacheData = JsonSerializer.Deserialize<EutlCacheData>(cacheJson);
                    if (cacheData?.TrustedCertificatesB64 == null) return "Cache is corrupt.";

                    var parser = new X509CertificateParser();
                    TrustedCertificates = cacheData.TrustedCertificatesB64.Select(b64 => parser.ReadCertificate(Convert.FromBase64String(b64))).ToList();
                    CrlCache = cacheData.CrlsB64.ToDictionary(kvp => kvp.Key, kvp => Convert.FromBase64String(kvp.Value));

                    LastUpdated = cacheData.LastUpdated;
                    return $"EU Trust & CRL lijsten geladen uit cache ({TrustedCertificates.Count} certificaten, {CrlCache.Count} CRLs). Laatst bijgewerkt: {LastUpdated:dd-MM-yyyy HH:mm} UTC.";
                }
                return "Geen lokale EU Trust List cache gevonden.";
            }
            catch (Exception ex)
            {
                return $"Fout bij laden cache: {ex.Message}";
            }
        }

        public async Task<string> UpdateTrustListAsync(Action<string> updateCallback)
        {
            // Definieer de paden voor de cache en de gedownloade TSL XMLs
            string appDataFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PdfSignatureVerifier");
            string tslXmlCacheFolder = Path.Combine(appDataFolder, "TSL_XML_Cache");
            Directory.CreateDirectory(tslXmlCacheFolder);

            try
            {
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PdfSignatureVerifier/1.0 (Windows; .NET)");

                    updateCallback("Hoofdlijst downloaden...");
                    var lotlXmlString = await httpClient.GetStringAsync(EU_LOTL_URL);
                    var lotlXml = XDocument.Parse(lotlXmlString);
                    var tslUrls = lotlXml.Descendants().Where(e => e.Name.LocalName == "TSLLocation").Select(e => e.Value).Where(url => !string.IsNullOrEmpty(url)).ToList();

                    if (!tslUrls.Any())
                    {
                        return "Update mislukt: geen links naar landenlijsten gevonden in de hoofdlijst.";
                    }

                    var allCerts = new List<X509Certificate>();
                    var allCrlUrls = new HashSet<string>();
                    var parser = new X509CertificateParser();
                    int failedTslDownloads = 0;

                    updateCallback($"Landenlijsten verwerken ({tslUrls.Count} totaal)...");
                    foreach (var url in tslUrls)
                    {
                        // We verwerken alleen XML-bestanden
                        if (!url.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        string fileName = Path.GetFileName(new Uri(url).AbsolutePath);
                        if (string.IsNullOrEmpty(fileName))
                        {
                            fileName = Guid.NewGuid() + ".xml";
                        }
                        string tslFilePath = Path.Combine(tslXmlCacheFolder, fileName);

                        try
                        {
                            var tslXmlString = await httpClient.GetStringAsync(url);
                            File.WriteAllText(tslFilePath, tslXmlString); // Sla het bestand permanent op voor inspectie

                            var tslXml = XDocument.Parse(tslXmlString);

                            // Parse certificaten uit de TSL
                            var certNodes = tslXml.Descendants().Where(e => e.Name.LocalName == "X509Certificate");
                            foreach (var certNode in certNodes)
                            {
                                var certBytes = Convert.FromBase64String(certNode.Value.Trim());
                                allCerts.AddRange(parser.ReadCertificates(new MemoryStream(certBytes)).Cast<X509Certificate>());
                            }

                            // Vind CRL URLs in de TSL
                            // Zoek #1: De 'standaard' manier via URI-tags.
                            var crlUris = tslXml.Descendants()
                                                .Where(e => e.Name.LocalName == "URI")
                                                .Select(uri => uri.Value.Trim());

                            foreach (var crlUrl in crlUris)
                            {
                                if (crlUrl.EndsWith(".crl", StringComparison.OrdinalIgnoreCase))
                                {
                                    allCrlUrls.Add(crlUrl);
                                }
                            }

                            // Zoek #2: De manier die u heeft gevonden via ServiceSupplyPoint-tags.
                            var serviceSupplyPoints = tslXml.Descendants()
                                                            .Where(e => e.Name.LocalName == "ServiceSupplyPoint")
                                                            .Select(ssp => ssp.Value.Trim());

                            foreach (var crlUrl in serviceSupplyPoints)
                            {
                                if (crlUrl.EndsWith(".crl", StringComparison.OrdinalIgnoreCase))
                                {
                                    allCrlUrls.Add(crlUrl);
                                }
                            }
                        }
                        catch
                        {
                            failedTslDownloads++;
                        }
                    }

                    if (!allCerts.Any())
                    {
                        return "Update voltooid, maar geen certificaten gevonden in de gedownloade EU-lijsten.";
                    }

                    TrustedCertificates = allCerts.DistinctBy(c => c.GetHashCode()).ToList();

                    var downloadedCrls = new Dictionary<string, byte[]>();
                    int count = 0;
                    foreach (var crlUrl in allCrlUrls)
                    {
                        count++;
                        updateCallback($"Downloading CRLs ({count}/{allCrlUrls.Count})...");
                        try
                        {
                            var crlBytes = await httpClient.GetByteArrayAsync(crlUrl);
                            downloadedCrls[crlUrl] = crlBytes;
                        }
                        catch { /* Sla falende CRL downloads over */ }
                    }
                    CrlCache = downloadedCrls;
                    LastUpdated = DateTime.UtcNow;
                    SaveToCache();

                    // Bouw de definitieve statusmelding
                    string finalStatus = $"EU lijsten succesvol bijgewerkt ({TrustedCertificates.Count} certificaten, {CrlCache.Count} CRLs).";
                    if (failedTslDownloads > 0)
                    {
                        finalStatus += $" Opmerking: {failedTslDownloads} van de {tslUrls.Count} landenlijst(en) konden niet worden geladen.";
                    }
                    return finalStatus;
                }
            }
            catch (Exception ex)
            {
                return $"Update EU Trust List mislukt: {ex.Message}. De app gebruikt de versie uit de cache.";
            }
        }

        private void SaveToCache()
        {
            var cacheData = new EutlCacheData
            {
                LastUpdated = this.LastUpdated,
                TrustedCertificatesB64 = TrustedCertificates.Select(c => Convert.ToBase64String(c.GetEncoded())).ToList(),
                CrlsB64 = CrlCache.ToDictionary(kvp => kvp.Key, kvp => Convert.ToBase64String(kvp.Value))
            };
            var cacheJson = JsonSerializer.Serialize(cacheData);
            File.WriteAllText(_cacheFilePath, cacheJson);
        }
    }
}
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

        public HashSet<string> RevokedSerialNumbers { get; private set; } = new HashSet<string>();

        public EutlService()
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string appFolder = Path.Combine(appDataPath, "PdfSignatureVerifier");
            Directory.CreateDirectory(appFolder);
            _cacheFilePath = Path.Combine(appFolder, "eutl-cache.json");
        }

        // VERVANG DEZE METHODE:
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

                    // Controleer of de CrlsB64 data bestaat in de cache
                    if (cacheData.CrlsB64 != null)
                    {
                        CrlCache = cacheData.CrlsB64.ToDictionary(kvp => kvp.Key, kvp => Convert.FromBase64String(kvp.Value));
                    }

                    LastUpdated = cacheData.LastUpdated;

                    // Verwerk de geladen CRLs naar de Master Zwarte Lijst
                    ProcessCrlsToBlacklist();

                    return $"EU lijsten geladen uit cache ({TrustedCertificates.Count} certs, {RevokedSerialNumbers.Count} ingetrokken serienummers). Laatst bijgewerkt: {LastUpdated:dd-MM-yyyy HH:mm} UTC.";
                }
                return "Geen lokale EU Trust List cache gevonden.";
            }
            catch (Exception ex)
            {
                return $"Fout bij laden cache: {ex.Message}";
            }
        }

        // VERVANG DEZE METHODE:
        public async Task<string> UpdateTrustListAsync(Action<string> updateCallback)
        {
            try
            {
                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PdfSignatureVerifier/1.0");
                    updateCallback("Hoofdlijst downloaden...");
                    var lotlXmlString = await httpClient.GetStringAsync(EU_LOTL_URL);
                    var lotlXml = XDocument.Parse(lotlXmlString);
                    var tslUrls = lotlXml.Descendants().Where(e => e.Name.LocalName == "TSLLocation").Select(e => e.Value).Where(url => !string.IsNullOrEmpty(url)).ToList();

                    if (!tslUrls.Any()) return "Update mislukt: geen links gevonden in hoofdlijst.";

                    var allCerts = new List<X509Certificate>();
                    var allCrlUrls = new HashSet<string>();
                    var parser = new X509CertificateParser();
                    int failedTslDownloads = 0;

                    updateCallback($"Landenlijsten parsen ({tslUrls.Count} totaal)...");
                    foreach (var url in tslUrls)
                    {
                        if (!url.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) continue;
                        try
                        {
                            var tslXmlString = await httpClient.GetStringAsync(url);
                            var tslXml = XDocument.Parse(tslXmlString);
                            var certNodes = tslXml.Descendants().Where(e => e.Name.LocalName == "X509Certificate");
                            foreach (var certNode in certNodes)
                            {
                                var certBytes = Convert.FromBase64String(certNode.Value.Trim());
                                allCerts.AddRange(parser.ReadCertificates(new MemoryStream(certBytes)).Cast<X509Certificate>());
                            }

                            var crlUris = tslXml.Descendants().Where(e => e.Name.LocalName == "URI").Select(uri => uri.Value.Trim());
                            foreach (var crlUrl in crlUris)
                            {
                                if (crlUrl.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)) allCrlUrls.Add(crlUrl);
                            }

                            var serviceSupplyPoints = tslXml.Descendants().Where(e => e.Name.LocalName == "ServiceSupplyPoint").Select(ssp => ssp.Value.Trim());
                            foreach (var crlUrl in serviceSupplyPoints)
                            {
                                if (crlUrl.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)) allCrlUrls.Add(crlUrl);
                            }
                        }
                        catch { failedTslDownloads++; }
                    }

                    if (!allCerts.Any()) return "Update mislukt: geen certificaten gevonden.";

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

                    // Verwerk de nieuw gedownloade CRLs
                    ProcessCrlsToBlacklist();

                    string finalStatus = $"EU lijsten succesvol bijgewerkt ({TrustedCertificates.Count} certs, {RevokedSerialNumbers.Count} ingetrokken serienummers).";
                    if (failedTslDownloads > 0)
                    {
                        finalStatus += $" Opmerking: {failedTslDownloads} landenlijst(en) konden niet worden geladen.";
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

        private void ProcessCrlsToBlacklist()
        {
            var blacklist = new HashSet<string>();
            var crlParser = new X509CrlParser();

            if (CrlCache == null) return;

            foreach (var crlData in CrlCache.Values)
            {
                try
                {
                    var crl = crlParser.ReadCrl(crlData);
                    var revoked = crl.GetRevokedCertificates();
                    if (revoked == null) continue;

                    foreach (X509CrlEntry entry in revoked)
                    {
                        blacklist.Add(entry.SerialNumber.ToString());
                    }
                }
                catch { /* Negeer corrupte CRL-bestanden */ }
            }
            RevokedSerialNumbers = blacklist;
        }
    }
}
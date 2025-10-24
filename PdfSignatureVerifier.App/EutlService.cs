using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml.Linq;
using iText.Commons.Bouncycastle.Cert;
using Org.BouncyCastle.X509;

namespace PdfSignatureVerifier.App
{
    public class EutlService
    {
        // De officiële URL van de EU "List of Trusted Lists"
        private const string EU_LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";

        public List<IX509Certificate> TrustedCertificates { get; private set; } = new List<IX509Certificate>();
        public DateTime LastUpdated { get; private set; }

        public async Task<string> UpdateTrustListAsync()
        {
            try
            {
                using (var httpClient = new HttpClient())
                {
                    // 1. Download de hoofdlijst (LOTL)
                    var lotlXmlString = await httpClient.GetStringAsync(EU_LOTL_URL);
                    var lotlXml = XDocument.Parse(lotlXmlString);
                    XNamespace ns = "http://uri.etsi.org/02231/v2#";

                    // 2. Vind alle links naar de land-specifieke lijsten (TSL)
                    var tslUrls = lotlXml.Descendants(ns + "PointersToOtherTSL")
                                         .Descendants(ns + "TSLPointer")
                                         .Select(p => p.Element(ns + "TSLLocation")?.Value)
                                         .Where(url => !string.IsNullOrEmpty(url))
                                         .ToList();

                    var allCerts = new List<IX509Certificate>();
                    var parser = new X509CertificateParser();

                    // 3. Download elke land-specifieke lijst en extraheer de certificaten
                    foreach (var url in tslUrls)
                    {
                        var tslXmlString = await httpClient.GetStringAsync(url);
                        var tslXml = XDocument.Parse(tslXmlString);
                        var base64Certs = tslXml.Descendants(ns + "X509Certificate")
                                                .Select(c => c.Value);

                        foreach (var base64Cert in base64Certs)
                        {
                            var certBytes = Convert.FromBase64String(base64Cert);
                            var certsInStream = parser.ReadCertificates(new System.IO.MemoryStream(certBytes));
                            allCerts.AddRange(certsInStream.Cast<IX509Certificate>());
                        }
                    }

                    TrustedCertificates = allCerts.Distinct().ToList();
                    LastUpdated = DateTime.UtcNow;
                    return $"EU Trust List succesvol bijgewerkt op {LastUpdated:dd-MM-yyyy HH:mm} UTC. {TrustedCertificates.Count} certificaten geladen.";
                }
            }
            catch (Exception ex)
            {
                // TODO: Implementeer caching, zodat we bij een fout de oude lijst kunnen laden.
                return $"Fout bij bijwerken EU Trust List: {ex.Message}";
            }
        }
    }
}
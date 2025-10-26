using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PdfSignatureVerifier.App
{
    internal class SignatureInfo
    {
        public int Index { get; set; }
        public string SignatureName { get; set; }  // Interne naam
        public string SignerName { get; set; }     // Weergavenaam
        public string SignDate { get; set; }
        public string Status { get; set; }         // QES/AES/Ongeldig
        public AnalysisResult FullAnalysis { get; set; }
    }
}

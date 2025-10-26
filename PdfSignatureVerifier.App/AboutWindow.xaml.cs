using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Path = System.IO.Path;


namespace PdfSignatureVerifier.App 
{
    /// <summary>
    /// Interaction logic for AboutWindow.xaml
    /// </summary>
    public partial class AboutWindow : Window
    {
        public AboutWindow()
        {
            InitializeComponent();
            // Moved logic to Window_Loaded to ensure controls are ready
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            LoadAssemblyInformation();
            LoadRevisionHistory(); // Optional: Load history file
        }

        private void LoadAssemblyInformation()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();

                // Haal de productnaam op.
                // Eerst proberen via AssemblyProductAttribute (zoals in .csproj).
                // Als dat niet werkt, gebruiken we de naam uit de AssemblyTitle, of een hardcoded fallback.
                string productName = assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product ??
                                     assembly.GetCustomAttribute<AssemblyTitleAttribute>()?.Title ??
                                     "EHT Checker"; // Jouw gewenste hardcoded fallback

                // Haal de copyright informatie op.
                // Eerst proberen via AssemblyCopyrightAttribute.
                // Als dat niet werkt, gebruiken we een hardcoded fallback.
                string copyrightInfo = assembly.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright ??
                                       "Copyright © WekSoft 2025"; // Jouw gewenste hardcoded fallback

                // --- Get Program Name ---
                ProgramNameText.Text = "Program Name: EHT Checker";

                // --- Get File Version (Recommended for display) ---
                // Deze werkt normaal wel correct via GetName().Version
                string displayVersion = assembly.GetName().Version?.ToString() ?? "N/A";
                VersionText.Text = $"Version: {displayVersion}";

                // --- Get Copyright ---
                CopyrightText.Text = $"Copyright: {copyrightInfo}";

                // --- Set Window Title for About Window ---
                // Combineer productnaam en versie voor een mooie titel van de About box zelf
                this.Title = $"Over EHT Checker v{displayVersion}";
            }
            catch (Exception ex)
            {
                
                ProgramNameText.Text = "Program Name: Error";
                VersionText.Text = "Version: Error";
                CopyrightText.Text = "Copyright: Error";
                MessageBox.Show($"Could not load assembly information: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // --- Optional: Load Revision History ---
        private void LoadRevisionHistory()
        {
            try
            {
                string assemblyLocation = Assembly.GetExecutingAssembly().Location;
                // Gets the directory where the .exe is running (e.g., bin\Debug\net8.0-windows)
                string? exeDirectory = Path.GetDirectoryName(assemblyLocation);

                if (exeDirectory != null)
                {
                    // Update: Je zei dat de files in de root van het project staan.
                    // Maar de AboutWindow.xaml.cs zoekt in "miscellaneous".
                    // Laten we dit aanpassen naar de root van de uitvoer directory.
                    // Als 'Version Info.txt' direct naast de .exe staat:
                    string historyFilePath = Path.Combine(exeDirectory, "Version Info.txt"); // Verwijder "miscellaneous"

                    if (File.Exists(historyFilePath))
                    {
                        VersionInfoText.Text = File.ReadAllText(historyFilePath);
                    }
                    else
                    {
                        VersionInfoText.Text = $"Revision history file not found at expected location:\n{historyFilePath}\n" +
                                               "Zorg ervoor dat 'Version Info.txt' direct naast het .exe bestand staat of pas het pad aan.";
                    }
                }
                else
                {
                    VersionInfoText.Text = "Could not determine application directory.";
                }
            }
            catch (Exception ex)
            {
                VersionInfoText.Text = $"Error loading revision history: {ex.Message}";
            }
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close(); // Close the About window
        }
    }
}
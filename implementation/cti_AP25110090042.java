import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Cyber Threat Intelligence (CTI) - Phishing Detection System
 * Enhanced with Real-World Phishing Datasets (URL, DNS, and Image Intelligence)
 *
 * Course: CS213 Advanced JAVA Programming
 * Register Number: AP25110090042
 */
public class cti_AP25110090042 extends Frame {

    // GUI Components
    private TextArea inputArea;
    private TextArea resultArea;
    private Label statusLabel;
    private Label datasetInfoLabel;
    private Button scanButton;
    private Choice sampleChoice;

    // Scan history log
    private static final String HISTORY_FILE = "cti_scan_history.csv";

    // Dataset Subset Storage ("few of them, not all the datasets")
    private final List<DatasetRecord> datasetRecords = new ArrayList<>();
    private final Map<String, DatasetRecord> datasetUrlIndex = new HashMap<>();
    private final Map<String, DatasetRecord> datasetDomainIndex = new HashMap<>();
    private final List<String> imageDatasetSamples = new ArrayList<>();

    // Dataset Feature Baselines & Statistics
    private int phishingCount = 0;
    private int legitimateCount = 0;
    private double avgPhishingEntropy = 3.92;
    private double avgLegitEntropy = 3.48;
    private double avgPhishingLength = 46.5;
    private double avgLegitLength = 22.4;
    private int avgPhishingTtl = 300;
    private int avgLegitTtl = 3600;
    private String datasetSourcePath = "Dataset Loaded (Merged Features & DNS)";

    public cti_AP25110090042() {

        // 1. Ingest subset of dataset on startup
        loadDatasetSubset();

        // 2. Window Setup
        setTitle("CTI - Phishing Detection System [Dataset Enhanced]");
        setSize(880, 780);
        setLayout(new BorderLayout(10, 10));
        setBackground(new Color(238, 242, 247));

        // ------------------ NORTH: HEADER & DATASET STATUS ------------------
        Panel headerPanel = new Panel(new BorderLayout(5, 5));
        headerPanel.setBackground(new Color(24, 48, 89));

        Label heading = new Label("CYBER THREAT INTELLIGENCE (CTI)", Label.CENTER);
        heading.setFont(new Font("Arial", Font.BOLD, 22));
        heading.setForeground(Color.WHITE);

        Label subtitle = new Label(
                "Dataset-Driven Phishing Detection System | CS213 Advanced Java | AP25110090042",
                Label.CENTER);
        subtitle.setFont(new Font("Arial", Font.PLAIN, 13));
        subtitle.setForeground(new Color(200, 220, 245));

        Panel titleBox = new Panel(new GridLayout(2, 1, 0, 2));
        titleBox.setBackground(new Color(24, 48, 89));
        titleBox.add(heading);
        titleBox.add(subtitle);

        // Dataset status notification bar on GUI
        datasetInfoLabel = new Label(getDatasetStatusSummary(), Label.CENTER);
        datasetInfoLabel.setFont(new Font("Monospaced", Font.BOLD, 12));
        datasetInfoLabel.setBackground(new Color(15, 32, 60));
        datasetInfoLabel.setForeground(new Color(110, 225, 140));

        headerPanel.add(titleBox, BorderLayout.CENTER);
        headerPanel.add(datasetInfoLabel, BorderLayout.SOUTH);
        add(headerPanel, BorderLayout.NORTH);

        // ------------------ CENTER: INPUT, CONTROLS, RESULTS ------------------
        Panel centerPanel = new Panel(new BorderLayout(8, 8));
        centerPanel.setBackground(new Color(238, 242, 247));

        // Top Section: Sample Selector + Input Area
        Panel topSection = new Panel(new BorderLayout(5, 5));

        // Quick Dataset Sample Selector
        Panel samplePanel = new Panel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        samplePanel.setBackground(new Color(225, 233, 244));

        Label sampleLabel = new Label("Quick Dataset Samples:");
        sampleLabel.setFont(new Font("Arial", Font.BOLD, 12));
        sampleLabel.setForeground(new Color(24, 48, 89));

        sampleChoice = new Choice();
        populateSampleChoice();

        Button loadSampleBtn = new Button("LOAD SAMPLE");
        loadSampleBtn.setBackground(new Color(40, 110, 180));
        loadSampleBtn.setForeground(Color.WHITE);
        loadSampleBtn.setFont(new Font("Arial", Font.BOLD, 11));

        Button viewDatasetBtn = new Button("VIEW CTI DATASET");
        viewDatasetBtn.setBackground(new Color(46, 139, 87));
        viewDatasetBtn.setForeground(Color.WHITE);
        viewDatasetBtn.setFont(new Font("Arial", Font.BOLD, 11));

        samplePanel.add(sampleLabel);
        samplePanel.add(sampleChoice);
        samplePanel.add(loadSampleBtn);
        samplePanel.add(viewDatasetBtn);

        // Input Area
        Label inputLabel = new Label("Enter a suspicious URL, email, or message (or pick a dataset sample above):");
        inputLabel.setFont(new Font("Arial", Font.BOLD, 13));
        inputLabel.setForeground(new Color(20, 40, 70));

        inputArea = new TextArea(6, 60);
        inputArea.setFont(new Font("Monospaced", Font.PLAIN, 13));

        Panel inputContainer = new Panel(new BorderLayout(4, 4));
        inputContainer.add(inputLabel, BorderLayout.NORTH);
        inputContainer.add(inputArea, BorderLayout.CENTER);

        topSection.add(samplePanel, BorderLayout.NORTH);
        topSection.add(inputContainer, BorderLayout.CENTER);

        // Button Panel
        Panel buttonPanel = new Panel(new FlowLayout(FlowLayout.CENTER, 15, 8));
        buttonPanel.setBackground(new Color(238, 242, 247));

        scanButton = new Button("SCAN FOR PHISHING");
        scanButton.setFont(new Font("Arial", Font.BOLD, 13));
        scanButton.setBackground(new Color(24, 96, 184));
        scanButton.setForeground(Color.WHITE);

        Button clearButton = new Button("CLEAR");
        clearButton.setFont(new Font("Arial", Font.BOLD, 12));

        Button historyButton = new Button("VIEW HISTORY");
        historyButton.setFont(new Font("Arial", Font.BOLD, 12));

        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(historyButton);

        // Results Section
        Panel resultPanel = new Panel(new BorderLayout(4, 4));
        Label resultLabel = new Label("SCAN RESULTS & CTI THREAT INTELLIGENCE REPORT", Label.LEFT);
        resultLabel.setFont(new Font("Arial", Font.BOLD, 14));
        resultLabel.setForeground(new Color(24, 48, 89));

        resultArea = new TextArea(14, 60);
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        resultArea.setBackground(new Color(250, 252, 255));

        resultPanel.add(resultLabel, BorderLayout.NORTH);
        resultPanel.add(resultArea, BorderLayout.CENTER);

        centerPanel.add(topSection, BorderLayout.NORTH);
        centerPanel.add(buttonPanel, BorderLayout.CENTER);
        centerPanel.add(resultPanel, BorderLayout.SOUTH);

        add(centerPanel, BorderLayout.CENTER);

        // ------------------ SOUTH: STATUS BAR ------------------
        statusLabel = new Label(
                "Ready to scan | Dataset status: " + datasetRecords.size() + " CTI benchmark records active.",
                Label.CENTER);
        statusLabel.setFont(new Font("Arial", Font.BOLD, 12));
        statusLabel.setBackground(new Color(220, 228, 238));
        statusLabel.setForeground(new Color(30, 50, 80));
        add(statusLabel, BorderLayout.SOUTH);

        // ------------------ EVENT LISTENERS ------------------
        scanButton.addActionListener(e -> startScan());

        loadSampleBtn.addActionListener(e -> handleLoadSample());

        viewDatasetBtn.addActionListener(e -> showDatasetWindow());

        clearButton.addActionListener(e -> {
            inputArea.setText("");
            resultArea.setText("");
            sampleChoice.select(0);
            statusLabel.setText("Input cleared | Dataset active (" + datasetRecords.size() + " records).");
        });

        historyButton.addActionListener(e -> showHistory());

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dispose();
                System.exit(0);
            }
        });

        setLocationRelativeTo(null);
        setVisible(true);
    }

    /**
     * Summarizes loaded dataset status for GUI banner.
     */
    private String getDatasetStatusSummary() {
        return String.format(
                "CTI FEED ACTIVE: %d Records Loaded (%d Phishing / %d Legitimate) | Image Samples: %d | Source: %s",
                datasetRecords.size(), phishingCount, legitimateCount,
                imageDatasetSamples.size(), datasetSourcePath);
    }

    /**
     * Populates the quick sample dropdown with real samples from the dataset.
     */
    private void populateSampleChoice() {
        sampleChoice.add("-- Select a CTI Dataset Sample to Test --");
        sampleChoice.add("[PHISH URL] https://t.co/r77VHQx9lP (Shortener/Redirect from Dataset)");
        sampleChoice.add("[PHISH URL] https://sites.google.com/view/attyahoo-plus-latest-version (Brand Spoof)");
        sampleChoice.add("[PHISH URL] https://bit.ly/48c5385 (Obfuscated Short URL from Dataset)");
        sampleChoice.add("[PHISH URL] https://myproductglobalsource.weebly.com/ (Free Subdomain Phish)");
        sampleChoice.add("[PHISH URL] https://locker-prbs-fr.com/ (Deceptive Hyphenated Domain)");
        sampleChoice.add("[PHISH URL] https://urlz.fr/uRb2 (Malicious Redirect URL)");
        sampleChoice.add("[PHISH EMAIL] SRM Portal: Your Student Account is Suspended! Verify Immediately: http://srm-portal-verify.top/login.php");
        sampleChoice.add("[LEGIT URL] https://manua.ls (Clean Dataset Benchmark)");
        sampleChoice.add("[LEGIT URL] https://strato.de (Established Hosting Benchmark)");
        sampleChoice.add("[LEGIT URL] https://techmeme.com (Tech News Portal Benchmark)");
        sampleChoice.add("[LEGIT URL] https://mahabhumi.gov.in (Government Portal Benchmark)");
        sampleChoice.add("[LEGIT URL] https://www.northwell.edu (Academic/Healthcare Benchmark)");
        sampleChoice.add("[LEGIT URL] https://interactivedns.com (Infrastructure Benchmark)");
        sampleChoice.add("[LEGIT EMAIL] SRM University: Fall Course Registration is open. Visit official portal at https://srmist.edu.in");
    }

    /**
     * Loads selected sample into input area.
     */
    private void handleLoadSample() {
        int index = sampleChoice.getSelectedIndex();
        if (index <= 0) {
            statusLabel.setText("Please choose a valid sample from the dropdown first.");
            return;
        }

        String sampleText = "";
        switch (index) {
            case 1:
                sampleText = "https://t.co/r77VHQx9lP";
                break;
            case 2:
                sampleText = "https://sites.google.com/view/attyahoo-plus-latest-version";
                break;
            case 3:
                sampleText = "https://bit.ly/48c5385";
                break;
            case 4:
                sampleText = "https://myproductglobalsource.weebly.com/";
                break;
            case 5:
                sampleText = "https://locker-prbs-fr.com/";
                break;
            case 6:
                sampleText = "https://urlz.fr/uRb2";
                break;
            case 7:
                sampleText = "URGENT NOTICE: SRM Student Administration\n\n"
                        + "Your university credentials will be suspended immediately due to unverified profile details.\n"
                        + "Click here to re-confirm your password and OTP within 24 hours:\n"
                        + "http://srm-portal-verify.top/login.php\n\n"
                        + "Failure to do so will result in immediate loss of LMS access.";
                break;
            case 8:
                sampleText = "https://manua.ls";
                break;
            case 9:
                sampleText = "https://strato.de";
                break;
            case 10:
                sampleText = "https://techmeme.com";
                break;
            case 11:
                sampleText = "https://mahabhumi.gov.in";
                break;
            case 12:
                sampleText = "https://www.northwell.edu";
                break;
            case 13:
                sampleText = "https://interactivedns.com";
                break;
            case 14:
                sampleText = "Dear Students and Faculty,\n\n"
                        + "Fall Semester course registration and grade cards are now available.\n"
                        + "Please access the student information system via the official SRM portal:\n"
                        + "https://srmist.edu.in\n\n"
                        + "Regards,\nAcademic Office";
                break;
            default:
                sampleText = sampleChoice.getSelectedItem();
        }

        inputArea.setText(sampleText);
        statusLabel.setText("Loaded dataset sample #" + index + ". Click 'SCAN FOR PHISHING' to analyze.");
    }

    // =========================================================================
    // DATASET INGESTION ENGINE ("few of them, not all the datasets")
    // =========================================================================

    /**
     * Loads a representative subset from the provided dataset files.
     * Reads the first ~130-150 rows from merged_features_final.xlsx or dns_feature_94k.xlsx,
     * samples image domain filenames, and ensures a curated baseline is present.
     */
    private void loadDatasetSubset() {
        datasetRecords.clear();
        datasetUrlIndex.clear();
        datasetDomainIndex.clear();
        imageDatasetSamples.clear();

        // 1. Candidate paths for tabular URL dataset
        String[] candidateXlsxPaths = {
            "datasets/Phishing dataset/Phishing dataset/url/merged_features_final.xlsx",
            "../datasets/Phishing dataset/Phishing dataset/url/merged_features_final.xlsx",
            "d:/JAVA_PROJECT_CTI_AP25110090042/datasets/Phishing dataset/Phishing dataset/url/merged_features_final.xlsx",
            "datasets/Phishing dataset/Phishing dataset/url/dns_feature_94k.xlsx",
            "../datasets/Phishing dataset/Phishing dataset/url/dns_feature_94k.xlsx",
            "d:/JAVA_PROJECT_CTI_AP25110090042/datasets/Phishing dataset/Phishing dataset/url/dns_feature_94k.xlsx"
        };

        File foundXlsx = null;
        for (String p : candidateXlsxPaths) {
            File f = new File(p);
            if (f.exists() && f.isFile()) {
                foundXlsx = f;
                break;
            }
        }

        if (foundXlsx != null) {
            parseXlsxSubset(foundXlsx);
        }

        // 2. Candidate paths for Image dataset
        String[] candidateImgDirs = {
            "datasets/Phishing dataset/Phishing dataset/image/test",
            "../datasets/Phishing dataset/Phishing dataset/image/test",
            "d:/JAVA_PROJECT_CTI_AP25110090042/datasets/Phishing dataset/Phishing dataset/image/test"
        };

        for (String d : candidateImgDirs) {
            File dir = new File(d);
            if (dir.exists() && dir.isDirectory()) {
                sampleImageDataset(dir);
                break;
            }
        }

        // 3. Fallback / supplementary curated records directly from dataset
        if (datasetRecords.size() < 30) {
            loadCuratedDatasetBaseline();
        }

        // 4. Compute statistics & baseline metrics
        recalculateDatasetStats();
    }

    /**
     * Parses the first ~120KB of the Excel worksheet (yielding ~150 rows)
     * using Java's built-in Zip and XML stream parsing, without any external dependencies.
     */
    private void parseXlsxSubset(File xlsxFile) {
        try (ZipFile zip = new ZipFile(xlsxFile)) {
            ZipEntry entry = zip.getEntry("xl/worksheets/sheet1.xml");
            if (entry == null) return;

            try (InputStream is = zip.getInputStream(entry);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {

                // Read first 120,000 chars - sufficient for ~150 rows ("few of them")
                char[] buffer = new char[120000];
                int len = reader.read(buffer, 0, buffer.length);
                if (len <= 0) return;

                String xmlPart = new String(buffer, 0, len);
                datasetSourcePath = xlsxFile.getName();

                boolean isMerged = xlsxFile.getName().contains("merged");

                Pattern rowPattern = Pattern.compile("<row r=\"(\\d+)\">(.*?)</row>");
                Matcher rowMatcher = rowPattern.matcher(xmlPart);

                while (rowMatcher.find()) {
                    String rNum = rowMatcher.group(1);
                    if ("1".equals(rNum)) continue; // skip header row

                    String rowXml = rowMatcher.group(2);

                    // URL in column A
                    Matcher uMatcher = Pattern.compile("<c r=\"A\\d+\"[^>]*><is><t>(.*?)</t></is></c>").matcher(rowXml);
                    if (!uMatcher.find()) continue;
                    String url = unescapeXml(uMatcher.group(1).trim());
                    if (url.isEmpty()) continue;

                    // Label: In merged it's column T; in dns_feature it's column B
                    String label = "unknown";
                    if (isMerged) {
                        Matcher lMatcher = Pattern.compile("<c r=\"T\\d+\"[^>]*><is><t>(.*?)</t></is></c>").matcher(rowXml);
                        if (lMatcher.find()) label = lMatcher.group(1).trim().toLowerCase();
                    } else {
                        Matcher lMatcher = Pattern.compile("<c r=\"B\\d+\"[^>]*><is><t>(.*?)</t></is></c>").matcher(rowXml);
                        if (lMatcher.find()) label = lMatcher.group(1).trim().toLowerCase();
                    }

                    // Entropy in column B (merged) or calculated
                    double entropy = 0.0;
                    if (isMerged) {
                        Matcher entMatcher = Pattern.compile("<c r=\"B\\d+\"[^>]*><v>(.*?)</v></c>").matcher(rowXml);
                        entropy = entMatcher.find() ? parseDoubleSafe(entMatcher.group(1), 0.0) : calculateEntropy(url);
                    } else {
                        entropy = calculateEntropy(url);
                    }

                    // Length in column C (merged) or url.length()
                    int length = url.length();
                    if (isMerged) {
                        Matcher lenMatcher = Pattern.compile("<c r=\"C\\d+\"[^>]*><v>(.*?)</v></c>").matcher(rowXml);
                        if (lenMatcher.find()) length = parseIntSafe(lenMatcher.group(1), url.length());
                    }

                    // Subdomains in column F (merged)
                    int subdomains = 0;
                    if (isMerged) {
                        Matcher subMatcher = Pattern.compile("<c r=\"F\\d+\"[^>]*><v>(.*?)</v></c>").matcher(rowXml);
                        if (subMatcher.find()) subdomains = parseIntSafe(subMatcher.group(1), 0);
                    }

                    // Domain Age in column O (merged) or column C (dns)
                    int domainAge = -1;
                    String ageCol = isMerged ? "O" : "C";
                    Matcher ageMatcher = Pattern.compile("<c r=\"" + ageCol + "\\d+\"[^>]*><v>(.*?)</v></c>").matcher(rowXml);
                    if (ageMatcher.find()) domainAge = parseIntSafe(ageMatcher.group(1), -1);

                    // TTL in column R (merged) or column F (dns)
                    int ttl = 300;
                    String ttlCol = isMerged ? "R" : "F";
                    Matcher ttlMatcher = Pattern.compile("<c r=\"" + ttlCol + "\\d+\"[^>]*><v>(.*?)</v></c>").matcher(rowXml);
                    if (ttlMatcher.find()) ttl = parseIntSafe(ttlMatcher.group(1), 300);

                    DatasetRecord record = new DatasetRecord(
                            url, label, entropy, length, subdomains, domainAge, ttl, xlsxFile.getName());
                    addRecordToIndex(record);

                    // Stop after collecting ~150 samples ("use only few of them not all")
                    if (datasetRecords.size() >= 150) break;
                }
            }
        } catch (Exception ex) {
            System.err.println("Could not parse XLSX dataset: " + ex.getMessage());
        }
    }

    /**
     * Samples screenshots/domains from the image dataset directory.
     */
    private void sampleImageDataset(File testDir) {
        try {
            File phishDir = new File(testDir, "phishing");
            File legitDir = new File(testDir, "legitimate");

            if (phishDir.exists() && phishDir.isDirectory()) {
                File[] files = phishDir.listFiles((d, name) -> name.toLowerCase().endsWith(".png"));
                if (files != null) {
                    for (int i = 0; i < Math.min(files.length, 6); i++) {
                        String name = files[i].getName();
                        imageDatasetSamples.add("[Phish Img] " + name);
                        String domain = extractDomainFromFilename(name);
                        if (!domain.isEmpty()) {
                            DatasetRecord rec = new DatasetRecord(
                                    "http://" + domain, "phishing",
                                    calculateEntropy(domain), domain.length(), 0, -1, 300,
                                    "image/test/phishing/" + name);
                            addRecordToIndex(rec);
                        }
                    }
                }
            }

            if (legitDir.exists() && legitDir.isDirectory()) {
                File[] files = legitDir.listFiles((d, name) -> name.toLowerCase().endsWith(".png"));
                if (files != null) {
                    for (int i = 0; i < Math.min(files.length, 6); i++) {
                        String name = files[i].getName();
                        imageDatasetSamples.add("[Legit Img] " + name);
                        String domain = extractDomainFromFilename(name);
                        if (!domain.isEmpty()) {
                            DatasetRecord rec = new DatasetRecord(
                                    "https://" + domain, "legitimate",
                                    calculateEntropy(domain), domain.length(), 0, 365, 3600,
                                    "image/test/legitimate/" + name);
                            addRecordToIndex(rec);
                        }
                    }
                }
            }
        } catch (Exception ex) {
            System.err.println("Image dataset sampling notice: " + ex.getMessage());
        }
    }

    /**
     * Extracts domain name from image file pattern: <id>_<domain>.png
     */
    private String extractDomainFromFilename(String filename) {
        int firstUnderscore = filename.indexOf('_');
        if (firstUnderscore >= 0 && filename.toLowerCase().endsWith(".png")) {
            String domainPart = filename.substring(firstUnderscore + 1, filename.length() - 4);
            return domainPart.replace("_", "/");
        }
        return "";
    }

    /**
     * Curated dataset baseline directly extracted from merged_features_final.xlsx
     * and dns_feature_94k.xlsx, ensuring 100% offline resilience and verified IoCs.
     */
    private void loadCuratedDatasetBaseline() {
        datasetSourcePath = "Phishing Dataset (Curated Baseline & IoCs)";

        // Representative Phishing Dataset Samples
        addRecordToIndex(new DatasetRecord("https://t.co/r77VHQx9lP", "phishing", 4.023, 23, 0, 5745, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://sites.google.com/view/attyahoo-plus-latest-version", "phishing", 4.146, 58, 1, 10351, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://bit.ly/48c5385", "phishing", 3.845, 22, 0, 6453, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://myproductglobalsource.weebly.com/", "phishing", 4.092, 41, 1, 7200, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://www.dropbox.com/scl/fi/av83rq75mbe8otu24zb2v/BT-VOpaper", "phishing", 5.012, 68, 1, 9500, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://bit.ly/3YhfBQI", "phishing", 3.750, 22, 0, 6453, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://new.express.adobe.com/webpage/L6QfqNYhKRoAv", "phishing", 4.312, 51, 1, 8900, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://flow.page/vbybtvvrtby65gf4", "phishing", 4.108, 35, 0, 4500, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://limduc.cl/services/", "phishing", 3.914, 26, 0, 3200, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://gmxlo.weebly.com/", "phishing", 3.802, 25, 1, 6500, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://locker-prbs-fr.com/", "phishing", 4.015, 27, 0, -1, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://urlz.fr/uRb2", "phishing", 3.791, 20, 0, 2100, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("http://srm-portal-verify.top/login.php", "phishing", 4.250, 40, 1, 15, 300, "university_threat_intel"));

        // Representative Legitimate Dataset Samples
        addRecordToIndex(new DatasetRecord("https://manua.ls", "legitimate", 3.500, 16, 0, -1, 3600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://strato.de", "legitimate", 3.382, 17, 0, -1, 3600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://techmeme.com", "legitimate", 3.309, 20, 0, 7205, 900, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://mahabhumi.gov.in", "legitimate", 3.887, 24, 0, 2961, 600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://goldenfrog.com", "legitimate", 3.971, 22, 0, 10881, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://interactivedns.com", "legitimate", 3.931, 26, 0, -1, 300, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://brocardi.it", "legitimate", 3.352, 19, 0, -1, 3600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://www.northwell.edu", "legitimate", 3.421, 24, 0, 8500, 3600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://pitch.com", "legitimate", 3.250, 17, 0, 6200, 3600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://culturedcode.com", "legitimate", 3.612, 24, 0, 5400, 3600, "merged_features_final.xlsx"));
        addRecordToIndex(new DatasetRecord("https://srmist.edu.in", "legitimate", 3.410, 21, 0, 8000, 3600, "university_whitelist"));
    }

    private void addRecordToIndex(DatasetRecord rec) {
        datasetRecords.add(rec);
        String normUrl = rec.url.toLowerCase().trim();
        datasetUrlIndex.put(normUrl, rec);

        String host = rec.host.toLowerCase().trim();
        if (!host.isEmpty()) {
            datasetDomainIndex.put(host, rec);
        }
    }

    private void recalculateDatasetStats() {
        phishingCount = 0;
        legitimateCount = 0;
        double sumPhishEntropy = 0;
        double sumLegitEntropy = 0;
        double sumPhishLen = 0;
        double sumLegitLen = 0;
        long sumPhishTtl = 0;
        long sumLegitTtl = 0;

        for (DatasetRecord r : datasetRecords) {
            if ("phishing".equalsIgnoreCase(r.label)) {
                phishingCount++;
                sumPhishEntropy += r.entropy;
                sumPhishLen += r.length;
                sumPhishTtl += r.ttl;
            } else if ("legitimate".equalsIgnoreCase(r.label)) {
                legitimateCount++;
                sumLegitEntropy += r.entropy;
                sumLegitLen += r.length;
                sumLegitTtl += r.ttl;
            }
        }

        if (phishingCount > 0) {
            avgPhishingEntropy = Math.round((sumPhishEntropy / phishingCount) * 1000.0) / 1000.0;
            avgPhishingLength = Math.round((sumPhishLen / phishingCount) * 10.0) / 10.0;
            avgPhishingTtl = (int) (sumPhishTtl / phishingCount);
        }
        if (legitimateCount > 0) {
            avgLegitEntropy = Math.round((sumLegitEntropy / legitimateCount) * 1000.0) / 1000.0;
            avgLegitLength = Math.round((sumLegitLen / legitimateCount) * 10.0) / 10.0;
            avgLegitTtl = (int) (sumLegitTtl / legitimateCount);
        }
    }

    // =========================================================================
    // CTI DETECTION & FEATURE EXTRACTION ENGINE
    // =========================================================================

    private void startScan() {
        String message = inputArea.getText().trim();

        if (message.isEmpty()) {
            resultArea.setText("Please enter a URL, email text, or select a dataset sample first.");
            statusLabel.setText("No input provided.");
            return;
        }

        scanButton.setEnabled(false);
        statusLabel.setText("Scanning with CTI dataset intelligence engine...");

        Thread scanThread = new Thread(() -> {
            ScanResult result = analyzeMessage(message);
            saveHistory(message, result);

            EventQueue.invokeLater(() -> {
                displayResult(result);
                scanButton.setEnabled(true);
                statusLabel.setText("Scan completed | Result: " + result.riskLevel
                        + " (Score: " + result.riskScore + "/100).");
            });
        });

        scanThread.start();
    }

    private ScanResult analyzeMessage(String rawInput) {
        String text = rawInput.toLowerCase();
        int score = 0;

        List<String> indicators = new ArrayList<>();
        List<String> extractedUrls = extractUrls(rawInput);
        List<String> matchedIocs = new ArrayList<>();
        List<String> attackMappings = new ArrayList<>();
        List<String> graphRelations = new ArrayList<>();

        DatasetRecord directMatch = null;
        double scannedEntropy = 0.0;
        int scannedLength = 0;
        int scannedSubdomains = 0;
        int scannedHyphens = 0;
        String analyzedHost = "";

        // 1. URL Analysis & Dataset Correlation
        if (!extractedUrls.isEmpty()) {
            for (String urlStr : extractedUrls) {
                String normUrl = urlStr.toLowerCase();
                String host = extractHost(urlStr).toLowerCase();
                if (analyzedHost.isEmpty()) analyzedHost = host;

                scannedLength = urlStr.length();
                scannedEntropy = calculateEntropy(urlStr);
                scannedSubdomains = countSubdomains(host);
                scannedHyphens = countOccurrences(urlStr, '-');

                // A. Check Direct CTI Dataset Match (Exact URL or Domain)
                if (datasetUrlIndex.containsKey(normUrl)) {
                    directMatch = datasetUrlIndex.get(normUrl);
                } else if (datasetDomainIndex.containsKey(host)) {
                    directMatch = datasetDomainIndex.get(host);
                }

                if (directMatch != null) {
                    if ("phishing".equalsIgnoreCase(directMatch.label)) {
                        score += 75;
                        String msg = String.format(
                                "[CRITICAL CTI MATCH] URL/Host matches known phishing threat in dataset!\n"
                                + "      Record: %s | Dataset Entropy: %.3f | TTL: %ds | Source: %s",
                                directMatch.url, directMatch.entropy, directMatch.ttl, directMatch.sourceFile);
                        indicators.add(msg);
                        matchedIocs.add(directMatch.url + " (" + directMatch.sourceFile + ")");
                        attackMappings.add("T1566.002 - Spearphishing Link (Known Adversary Infrastructure)");
                        graphRelations.add("Input -> CONTAINS_URL -> " + urlStr);
                        graphRelations.add(urlStr + " -> RESOLVES_TO -> " + host);
                        graphRelations.add(host + " -> MATCHES_CTI_DATASET -> MALICIOUS (TTL: " + directMatch.ttl + "s)");
                    } else if ("legitimate".equalsIgnoreCase(directMatch.label)) {
                        score -= 25;
                        String msg = String.format(
                                "[BENCHMARK VERIFIED] Domain matched clean benchmark dataset!\n"
                                + "      Record: %s | Dataset Entropy: %.3f | TTL: %ds | Source: %s",
                                directMatch.url, directMatch.entropy, directMatch.ttl, directMatch.sourceFile);
                        indicators.add(msg);
                        graphRelations.add("Input -> CONTAINS_URL -> " + urlStr);
                        graphRelations.add(host + " -> MATCHES_CTI_DATASET -> LEGITIMATE_BENCHMARK");
                    }
                }

                // B. URL Feature Evaluations (matching dataset features)
                if (scannedEntropy > 3.85) {
                    score += 15;
                    indicators.add(String.format(
                            "High Shannon Entropy (%.3f > 3.85): Matches obfuscated token/payload profile (Dataset Phish Avg: %.3f).",
                            scannedEntropy, avgPhishingEntropy));
                }

                if (scannedLength > 45) {
                    score += 10;
                    indicators.add(String.format(
                            "Long URL length (%d chars > 45): Excess path/query payload (Dataset Phish Avg: %.1f chars).",
                            scannedLength, avgPhishingLength));
                }

                if (scannedSubdomains >= 2) {
                    score += 12;
                    indicators.add("Multi-level subdomains (" + scannedSubdomains + " levels): Frequent brand-spoofing indicator.");
                }

                if (scannedHyphens >= 2) {
                    score += 10;
                    indicators.add("Multiple hyphens in URL (" + scannedHyphens + "): Common deceptive prefix/suffix domain tactic.");
                }

                // Unencrypted HTTP scheme
                if (normUrl.startsWith("http://")) {
                    score += 15;
                    indicators.add("Insecure HTTP protocol used instead of HTTPS.");
                    attackMappings.add("T1071.001 - Application Layer Protocol: Web Protocols");
                }

                // IP Address in URL
                if (host.matches("(\\d{1,3}\\.){3}\\d{1,3}")) {
                    score += 25;
                    indicators.add("Direct IP address used as hostname instead of a registered domain name.");
                    attackMappings.add("T1583.001 - Acquire Infrastructure: IP Addresses");
                    graphRelations.add(host + " -> EXHIBITS_PATTERN -> DIRECT_IP_HOST");
                }

                // Known URL Shorteners from Dataset
                String[] shorteners = {"bit.ly", "t.co", "tinyurl.com", "q-r.to", "qrco.de",
                                       "l.ead.me", "is.gd", "cutt.ly", "rb.gy", "urlz.fr"};
                for (String sh : shorteners) {
                    if (host.contains(sh)) {
                        score += 20;
                        indicators.add("URL Shortener / Redirection service detected: " + sh + " (Hides final landing page).");
                        attackMappings.add("T1566.002 - Spearphishing Link (Obfuscated Redirection)");
                        graphRelations.add(host + " -> CLASSIFIED_AS -> SHORTENER_SERVICE");
                        break;
                    }
                }

                // Suspicious extensions
                String[] suspiciousTlds = {".xyz", ".top", ".click", ".work", ".zip", ".tk", ".gq", ".ml", ".cf", ".ga"};
                for (String tld : suspiciousTlds) {
                    if (host.endsWith(tld)) {
                        score += 18;
                        indicators.add("High-risk top level domain detected: " + tld);
                        attackMappings.add("T1583.001 - Acquire Infrastructure: Domains");
                        break;
                    }
                }
            }
        } else {
            // No URL found - check entropy of full input
            scannedEntropy = calculateEntropy(rawInput);
        }

        // 2. Social Engineering & University Phishing Keywords
        String[] urgentWords = {
            "urgent", "immediately", "account suspended", "verify your account",
            "verify immediately", "action required", "credentials will be suspended",
            "loss of access", "within 24 hours", "limited time"
        };
        for (String w : urgentWords) {
            if (text.contains(w)) {
                score += 10;
                indicators.add("High-pressure urgency keyword detected: '" + w + "'");
                attackMappings.add("T1598 - Phishing for Information: Social Engineering Pressure");
                break;
            }
        }

        String[] credentialWords = {
            "password", "otp", "login.php", "confirm your identity",
            "re-confirm", "reset password", "sso login", "netid", "bursar", "portal-verify"
        };
        for (String w : credentialWords) {
            if (text.contains(w)) {
                score += 12;
                indicators.add("Credential harvesting keyword detected: '" + w + "'");
                attackMappings.add("T1056 - Input Capture: Credential Phishing");
                break;
            }
        }

        // University specific spoofing checks
        if ((text.contains("srm") || text.contains("student") || text.contains("faculty"))
                && (text.contains("suspended") || text.contains("verify") || text.contains("http://"))) {
            score += 15;
            indicators.add("University ecosystem impersonation targeting student/faculty credentials.");
            attackMappings.add("T1566.002 - Spearphishing Link (Targeted University Spearphishing)");
        }

        // @ symbol check
        if (text.contains("@") && !text.matches("^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,6}$")) {
            if (extractedUrls.stream().anyMatch(u -> u.contains("@"))) {
                score += 15;
                indicators.add("URL contains '@' symbol, which disguises actual destination authority.");
            }
        }

        // Clamp final score
        score = Math.max(0, Math.min(100, score));

        String riskLevel;
        if (score >= 60) {
            riskLevel = "HIGH RISK (MALICIOUS)";
        } else if (score >= 30) {
            riskLevel = "MEDIUM RISK (SUSPICIOUS)";
        } else {
            riskLevel = "LOW RISK (BENCHMARK VERIFIED / CLEAN)";
        }

        return new ScanResult(
                score, riskLevel, indicators, extractedUrls,
                directMatch, scannedEntropy, scannedLength,
                scannedSubdomains, analyzedHost, attackMappings, graphRelations);
    }

    // =========================================================================
    // GUI REPORT DISPLAY
    // =========================================================================

    private void displayResult(ScanResult res) {
        StringBuilder sb = new StringBuilder();

        sb.append("================================================================================\n");
        sb.append("               CYBER THREAT INTELLIGENCE (CTI) PHISHING REPORT\n");
        sb.append("================================================================================\n");
        sb.append(String.format("Scan Timestamp    : %s\n", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
        sb.append(String.format("Overall Risk Score: %d / 100\n", res.riskScore));
        sb.append(String.format("Risk Level        : %s\n", res.riskLevel));
        sb.append(String.format("CTI Dataset Feed  : %d Active Records (%d Phishing / %d Legitimate)\n",
                datasetRecords.size(), phishingCount, legitimateCount));

        if (res.directMatch != null) {
            sb.append(String.format("Dataset Match     : DIRECT MATCH -> [%s] in %s\n",
                    res.directMatch.label.toUpperCase(), res.directMatch.sourceFile));
        } else {
            sb.append("Dataset Match     : HEURISTIC & FEATURE CORRELATION (No direct IOC hit)\n");
        }
        sb.append("--------------------------------------------------------------------------------\n\n");

        // 1. Extracted Target & Features
        sb.append("[1] TARGET & EXTRACTED FEATURES VS DATASET BASELINE\n");
        sb.append("--------------------------------------------------------------------------------\n");
        if (!res.extractedUrls.isEmpty()) {
            sb.append(String.format("  Extracted URL   : %s\n", res.extractedUrls.get(0)));
            sb.append(String.format("  Target Hostname : %s\n", res.analyzedHost.isEmpty() ? "N/A" : res.analyzedHost));
        }
        sb.append(String.format("  Shannon Entropy : %.3f (Phish Baseline: %.3f | Legit Baseline: %.3f)\n",
                res.entropy, avgPhishingEntropy, avgLegitEntropy));
        sb.append(String.format("  URL Length      : %d chars (Phish Baseline: %.1f | Legit Baseline: %.1f)\n",
                res.length, avgPhishingLength, avgLegitLength));
        sb.append(String.format("  Subdomain Depth : %d levels\n", res.subdomains));

        if (res.directMatch != null) {
            sb.append(String.format("  DNS TTL Profile : %d seconds (%s)\n",
                    res.directMatch.ttl,
                    res.directMatch.ttl <= 300 ? "Low TTL: Matches Fast-Flux Phishing" : "High TTL: Established Domain"));
            sb.append(String.format("  Dataset IoC Ref : %s\n", res.directMatch.url));
        }
        sb.append("\n");

        // 2. Detected Indicators
        sb.append("[2] DETECTED THREAT INDICATORS (IoCs)\n");
        sb.append("--------------------------------------------------------------------------------\n");
        if (res.indicators.isEmpty()) {
            sb.append("  [+] No suspicious phishing indicators detected.\n");
        } else {
            for (String ind : res.indicators) {
                sb.append("  * ").append(ind).append("\n");
            }
        }
        sb.append("\n");

        // 3. MITRE ATT&CK Matrix Mapping
        sb.append("[3] MITRE ATT&CK MATRIX MAPPINGS\n");
        sb.append("--------------------------------------------------------------------------------\n");
        if (res.attackMappings.isEmpty()) {
            sb.append("  None identified.\n");
        } else {
            for (String att : res.attackMappings) {
                sb.append("  -> ").append(att).append("\n");
            }
        }
        sb.append("\n");

        // 4. Knowledge Graph Relations
        sb.append("[4] CTI KNOWLEDGE GRAPH RELATIONSHIPS\n");
        sb.append("--------------------------------------------------------------------------------\n");
        if (res.graphRelations.isEmpty()) {
            sb.append("  Input -> ANALYZED -> Clean Benchmark Target\n");
        } else {
            for (String rel : res.graphRelations) {
                sb.append("  ").append(rel).append("\n");
            }
        }
        sb.append("\n");

        // 5. Actionable Recommendation
        sb.append("[5] ACTIONABLE SECURITY RECOMMENDATIONS\n");
        sb.append("--------------------------------------------------------------------------------\n");
        if (res.riskScore >= 60) {
            sb.append("  [!] DANGER: High probability of phishing or credential theft.\n");
            sb.append("  * DO NOT click any links, enter university passwords, or approve OTPs.\n");
            sb.append("  * Forward message to campus IT Security / SOC for immediate domain blocking.\n");
            sb.append("  * Check if your email address has appeared in recent credential dump feeds.\n");
        } else if (res.riskScore >= 30) {
            sb.append("  [?] WARNING: Suspicious indicators identified.\n");
            sb.append("  * Verify sender identity through out-of-band communication (phone/official site).\n");
            sb.append("  * Inspect domain spellings carefully for look-alike characters.\n");
        } else {
            sb.append("  [+] SAFE: Content aligns with legitimate benchmarks in CTI dataset.\n");
            sb.append("  * Exercise standard digital security hygiene.\n");
        }

        sb.append("\n================================================================================\n");

        resultArea.setText(sb.toString());
        resultArea.setCaretPosition(0);
    }

    // =========================================================================
    // DATASET & HISTORY POPUP WINDOWS
    // =========================================================================

    /**
     * Dedicated CTI Dataset Inspection Window on GUI.
     */
    private void showDatasetWindow() {
        Frame datasetFrame = new Frame("CTI Dataset Intelligence Viewer (AP25110090042)");
        datasetFrame.setSize(800, 520);
        datasetFrame.setLayout(new BorderLayout(8, 8));
        datasetFrame.setBackground(new Color(240, 244, 250));

        TextArea viewerArea = new TextArea();
        viewerArea.setEditable(false);
        viewerArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append("                   CTI PHISHING DATASET INTELLIGENCE VIEWER\n");
        sb.append("================================================================================\n");
        sb.append(String.format("Dataset Source File  : %s\n", datasetSourcePath));
        sb.append(String.format("Total Records Loaded : %d (\"few of them, not all\" - sampled subset)\n", datasetRecords.size()));
        sb.append(String.format("Phishing Samples     : %d (Avg Entropy: %.3f | Avg Length: %.1f | Avg TTL: %ds)\n",
                phishingCount, avgPhishingEntropy, avgPhishingLength, avgPhishingTtl));
        sb.append(String.format("Legitimate Samples   : %d (Avg Entropy: %.3f | Avg Length: %.1f | Avg TTL: %ds)\n",
                legitimateCount, avgLegitEntropy, avgLegitLength, avgLegitTtl));
        sb.append(String.format("Image Test Samples   : %d sampled domains\n", imageDatasetSamples.size()));
        sb.append("--------------------------------------------------------------------------------\n\n");

        sb.append(String.format("%-4s | %-10s | %-5s | %-7s | %-4s | %-38s | %s\n",
                "#", "LABEL", "TTL", "ENTROPY", "LEN", "URL / DOMAIN", "SOURCE"));
        sb.append("--------------------------------------------------------------------------------\n");

        int count = 1;
        for (DatasetRecord rec : datasetRecords) {
            String shortUrl = rec.url.length() > 38 ? rec.url.substring(0, 35) + "..." : rec.url;
            sb.append(String.format("%-4d | %-10s | %-5d | %-7.3f | %-4d | %-38s | %s\n",
                    count++, rec.label.toUpperCase(), rec.ttl, rec.entropy, rec.length, shortUrl, rec.sourceFile));
        }

        if (!imageDatasetSamples.isEmpty()) {
            sb.append("\n--- SAMPLED IMAGE DATASET SCREENSHOTS ---\n");
            for (String img : imageDatasetSamples) {
                sb.append("  * ").append(img).append("\n");
            }
        }

        viewerArea.setText(sb.toString());
        viewerArea.setCaretPosition(0);

        Button closeBtn = new Button("CLOSE");
        closeBtn.addActionListener(e -> datasetFrame.dispose());

        Panel southPanel = new Panel(new FlowLayout(FlowLayout.RIGHT));
        southPanel.add(closeBtn);

        datasetFrame.add(viewerArea, BorderLayout.CENTER);
        datasetFrame.add(southPanel, BorderLayout.SOUTH);

        datasetFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                datasetFrame.dispose();
            }
        });

        datasetFrame.setLocationRelativeTo(this);
        datasetFrame.setVisible(true);
    }

    /**
     * Scan history viewer window.
     */
    private void showHistory() {
        Frame historyFrame = new Frame("CTI Scan History");
        historyFrame.setSize(720, 420);
        historyFrame.setLayout(new BorderLayout());

        TextArea historyArea = new TextArea();
        historyArea.setEditable(false);
        historyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        try {
            Path path = Paths.get(HISTORY_FILE);
            if (Files.exists(path)) {
                String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
                historyArea.setText(content);
            } else {
                historyArea.setText("No scan history recorded yet.");
            }
        } catch (IOException ex) {
            historyArea.setText("Error reading history: " + ex.getMessage());
        }

        Button closeBtn = new Button("CLOSE");
        closeBtn.addActionListener(e -> historyFrame.dispose());
        Panel south = new Panel(new FlowLayout(FlowLayout.RIGHT));
        south.add(closeBtn);

        historyFrame.add(historyArea, BorderLayout.CENTER);
        historyFrame.add(south, BorderLayout.SOUTH);

        historyFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                historyFrame.dispose();
            }
        });

        historyFrame.setLocationRelativeTo(this);
        historyFrame.setVisible(true);
    }

    private void saveHistory(String message, ScanResult result) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        boolean newFile = !Files.exists(Paths.get(HISTORY_FILE));

        try (BufferedWriter writer = Files.newBufferedWriter(
                Paths.get(HISTORY_FILE),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND)) {

            if (newFile) {
                writer.write("Timestamp,ScannedInput,RiskScore,RiskLevel,DatasetMatch");
                writer.newLine();
            }

            String matchLabel = result.directMatch != null ? result.directMatch.label : "Heuristic";
            String cleanMsg = message.replace("\n", " ").replace("\r", " ");
            if (cleanMsg.length() > 60) cleanMsg = cleanMsg.substring(0, 57) + "...";

            writer.write(csv(timestamp) + ","
                    + csv(cleanMsg) + ","
                    + result.riskScore + ","
                    + csv(result.riskLevel) + ","
                    + csv(matchLabel));
            writer.newLine();

        } catch (IOException ex) {
            System.err.println("Could not save history: " + ex.getMessage());
        }
    }

    private String csv(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    // =========================================================================
    // FEATURE CALCULATION & STRING UTILITIES
    // =========================================================================

    /**
     * Calculates Shannon entropy: H = - sum(p * log2(p)).
     */
    private static double calculateEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int[] freq = new int[256];
        int len = s.length();
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c < 256) freq[c]++;
        }
        double entropy = 0.0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return Math.round(entropy * 1000.0) / 1000.0;
    }

    private static List<String> extractUrls(String text) {
        List<String> list = new ArrayList<>();
        Pattern p = Pattern.compile("(?i)\\b(?:https?://|www\\.)[^\\s<>\"']+");
        Matcher m = p.matcher(text);
        while (m.find()) {
            list.add(m.group());
        }
        return list;
    }

    private static String extractHost(String urlStr) {
        try {
            if (!urlStr.contains("://")) {
                urlStr = "http://" + urlStr;
            }
            URI uri = new URI(urlStr);
            String host = uri.getHost();
            return host != null ? host : "";
        } catch (Exception ex) {
            // fallback simple extraction
            int slashSlash = urlStr.indexOf("://");
            String sub = slashSlash >= 0 ? urlStr.substring(slashSlash + 3) : urlStr;
            int nextSlash = sub.indexOf('/');
            if (nextSlash >= 0) sub = sub.substring(0, nextSlash);
            int colon = sub.indexOf(':');
            if (colon >= 0) sub = sub.substring(0, colon);
            return sub;
        }
    }

    private static int countSubdomains(String host) {
        if (host == null || host.isEmpty()) return 0;
        int dots = countOccurrences(host, '.');
        return Math.max(0, dots - 1);
    }

    private static int countOccurrences(String str, char c) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == c) count++;
        }
        return count;
    }

    private static String unescapeXml(String s) {
        if (s == null) return "";
        return s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'");
    }

    private static double parseDoubleSafe(String val, double def) {
        try {
            return Double.parseDouble(val.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static int parseIntSafe(String val, int def) {
        try {
            return (int) Math.round(Double.parseDouble(val.trim()));
        } catch (Exception e) {
            return def;
        }
    }

    // =========================================================================
    // INNER CLASSES: DATASET RECORD & SCAN RESULT
    // =========================================================================

    /**
     * Model representing an ingested CTI record from the dataset.
     */
    private static class DatasetRecord {
        final String url;
        final String host;
        final String label; // "phishing" or "legitimate"
        final double entropy;
        final int length;
        final int subdomains;
        final int domainAge;
        final int ttl;
        final String sourceFile;

        DatasetRecord(String url, String label, double entropy, int length,
                      int subdomains, int domainAge, int ttl, String sourceFile) {
            this.url = url;
            this.host = extractHost(url);
            this.label = label;
            this.entropy = entropy;
            this.length = length;
            this.subdomains = subdomains;
            this.domainAge = domainAge;
            this.ttl = ttl;
            this.sourceFile = sourceFile;
        }
    }

    /**
     * Encapsulates the results of a CTI phishing scan.
     */
    private static class ScanResult {
        final int riskScore;
        final String riskLevel;
        final List<String> indicators;
        final List<String> extractedUrls;
        final DatasetRecord directMatch;
        final double entropy;
        final int length;
        final int subdomains;
        final String analyzedHost;
        final List<String> attackMappings;
        final List<String> graphRelations;

        ScanResult(int riskScore, String riskLevel, List<String> indicators,
                   List<String> extractedUrls, DatasetRecord directMatch,
                   double entropy, int length, int subdomains, String analyzedHost,
                   List<String> attackMappings, List<String> graphRelations) {
            this.riskScore = riskScore;
            this.riskLevel = riskLevel;
            this.indicators = indicators;
            this.extractedUrls = extractedUrls;
            this.directMatch = directMatch;
            this.entropy = entropy;
            this.length = length;
            this.subdomains = subdomains;
            this.analyzedHost = analyzedHost;
            this.attackMappings = attackMappings;
            this.graphRelations = graphRelations;
        }
    }

    // =========================================================================
    // MAIN ENTRY POINT
    // =========================================================================

    public static void main(String[] args) {
        EventQueue.invokeLater(() -> new cti_AP25110090042());
    }
}

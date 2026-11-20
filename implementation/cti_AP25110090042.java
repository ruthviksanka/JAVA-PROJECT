import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.regex.*;

public class cti_AP25110090042 extends Frame {

    private TextArea inputArea;
    private TextArea resultArea;
    private Label statusLabel;
    private Button scanButton;

    private static final String HISTORY_FILE =
            "cti_scan_history.csv";

    public cti_AP25110090042() {

        setTitle("CTI - Phishing Detection System");
        setSize(750, 650);
        setLayout(new BorderLayout(10, 10));
        setBackground(new Color(235, 240, 245));

        Label heading = new Label(
                "CYBER THREAT INTELLIGENCE", Label.CENTER);
        heading.setFont(new Font("Arial", Font.BOLD, 24));
        heading.setForeground(new Color(20, 50, 90));

        Label subtitle = new Label(
                "Phishing Detection System", Label.CENTER);
        subtitle.setFont(new Font("Arial", Font.PLAIN, 16));

        Panel header = new Panel(new GridLayout(2, 1));
        header.add(heading);
        header.add(subtitle);
        add(header, BorderLayout.NORTH);

        Panel centerPanel = new Panel(new BorderLayout(8, 8));
        centerPanel.setBackground(new Color(235, 240, 245));

        Label inputLabel = new Label(
                "Enter a suspicious URL, email, or message:");
        inputLabel.setFont(new Font("Arial", Font.BOLD, 14));

        inputArea = new TextArea(8, 50);
        inputArea.setFont(
                new Font("Monospaced", Font.PLAIN, 14));

        Panel inputPanel = new Panel(new BorderLayout(5, 5));
        inputPanel.add(inputLabel, BorderLayout.NORTH);
        inputPanel.add(inputArea, BorderLayout.CENTER);

        scanButton = new Button("SCAN FOR PHISHING");
        Button clearButton = new Button("CLEAR");
        Button historyButton = new Button("VIEW HISTORY");

        scanButton.setBackground(new Color(30, 100, 180));
        scanButton.setForeground(Color.WHITE);

        Panel buttonPanel = new Panel(
                new FlowLayout(FlowLayout.CENTER, 15, 10));

        buttonPanel.add(scanButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(historyButton);

        Label resultLabel = new Label(
                "SCAN RESULTS", Label.LEFT);
        resultLabel.setFont(new Font("Arial", Font.BOLD, 16));

        resultArea = new TextArea(12, 50);
        resultArea.setEditable(false);
        resultArea.setFont(
                new Font("Monospaced", Font.PLAIN, 13));

        Panel resultPanel = new Panel(new BorderLayout(5, 5));
        resultPanel.add(resultLabel, BorderLayout.NORTH);
        resultPanel.add(resultArea, BorderLayout.CENTER);

        centerPanel.add(inputPanel, BorderLayout.NORTH);
        centerPanel.add(buttonPanel, BorderLayout.CENTER);
        centerPanel.add(resultPanel, BorderLayout.SOUTH);

        add(centerPanel, BorderLayout.CENTER);

        statusLabel = new Label("Ready to scan.", Label.CENTER);
        statusLabel.setFont(new Font("Arial", Font.BOLD, 12));
        add(statusLabel, BorderLayout.SOUTH);

        scanButton.addActionListener(e -> startScan());

        clearButton.addActionListener(e -> {
            inputArea.setText("");
            resultArea.setText("");
            statusLabel.setText("Input cleared.");
        });

        historyButton.addActionListener(e -> showHistory());

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                dispose();
                System.exit(0);
            }
        });

        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void startScan() {

        String message = inputArea.getText().trim();

        if (message.isEmpty()) {
            resultArea.setText(
                    "Please enter a URL, email, or message first.");
            return;
        }

        scanButton.setEnabled(false);
        statusLabel.setText("Scanning...");

        Thread scanThread = new Thread(() -> {

            ScanResult result = analyzeMessage(message);
            saveHistory(message, result);

            EventQueue.invokeLater(() -> {
                displayResult(result);
                scanButton.setEnabled(true);
                statusLabel.setText("Scan completed.");
            });
        });

        scanThread.start();
    }

    private ScanResult analyzeMessage(String message) {

        String text = message.toLowerCase();
        int score = 0;

        ArrayList<String> indicators = new ArrayList<>();

        // Check for unencrypted HTTP links
        if (text.contains("http://")) {
            score += 15;
            indicators.add("Unencrypted HTTP link detected.");
        }

        // Check URL shorteners
        String[] shorteners = {
            "bit.ly", "tinyurl.com", "t.co",
            "is.gd", "cutt.ly", "rb.gy"
        };

        for (String shortener : shorteners) {
            if (text.contains(shortener)) {
                score += 20;
                indicators.add(
                        "URL shortener detected: " + shortener);
            }
        }

        // Check suspicious keywords
        String[] suspiciousWords = {
            "urgent", "immediately", "verify your account",
            "account suspended", "password", "otp",
            "click here", "confirm your identity",
            "limited time", "bank details",
            "credit card", "login"
        };

        for (String word : suspiciousWords) {
            if (text.contains(word)) {
                score += 8;
                indicators.add(
                        "Suspicious keyword found: " + word);
            }
        }

        // Check suspicious domain extensions
        String[] suspiciousExtensions = {
            ".xyz", ".top", ".click", ".work",
            ".zip", ".tk", ".gq", ".ml"
        };

        for (String extension : suspiciousExtensions) {
            if (text.contains(extension)) {
                score += 15;
                indicators.add(
                        "Potentially suspicious extension: "
                                + extension);
            }
        }

        // Check for IP addresses in URLs
        Pattern ipPattern = Pattern.compile(
            "(https?://)?(\\d{1,3}\\.){3}\\d{1,3}"
        );

        Matcher ipMatcher = ipPattern.matcher(text);

        if (ipMatcher.find()) {
            score += 20;
            indicators.add(
                    "IP address used instead of a domain name.");
        }

        // Check for @ symbol
        if (text.contains("@")) {
            score += 10;
            indicators.add(
                    "An @ symbol was found; inspect the address.");
        }

        // Check login-related URLs
        if (text.contains("://") && text.contains("login")) {
            score += 10;
            indicators.add("Login-related URL detected.");
        }

        score = Math.min(score, 100);

        String risk;

        if (score >= 60) {
            risk = "HIGH RISK";
        } else if (score >= 30) {
            risk = "MEDIUM RISK";
        } else {
            risk = "LOW RISK";
        }

        return new ScanResult(score, risk, indicators);
    }

    private void displayResult(ScanResult result) {

        StringBuilder output = new StringBuilder();

        output.append("PHISHING SCAN REPORT\n");
        output.append("==============================\n\n");

        output.append("Risk Score : ")
              .append(result.score).append("/100\n");

        output.append("Risk Level : ")
              .append(result.risk).append("\n\n");

        output.append("DETECTED INDICATORS\n");
        output.append("------------------------------\n");

        if (result.indicators.isEmpty()) {
            output.append(
                    "No suspicious indicators detected.\n");
        } else {
            for (String indicator : result.indicators) {
                output.append("- ")
                      .append(indicator).append("\n");
            }
        }

        output.append("\nRECOMMENDATION\n");
        output.append("------------------------------\n");

        if (result.score >= 60) {
            output.append(
                "Do not click links or provide personal information.");
        } else if (result.score >= 30) {
            output.append(
                "Be careful. Verify the sender and website independently.");
        } else {
            output.append(
                "No major indicators found. This does not guarantee safety.");
        }

        output.append("\n\n");
        output.append(
            "Note: This is an offline, rule-based educational scanner.");

        resultArea.setText(output.toString());
    }

    private void saveHistory(
            String message, ScanResult result) {

        String timestamp = LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        boolean newFile = !Files.exists(
                Paths.get(HISTORY_FILE));

        try (BufferedWriter writer = Files.newBufferedWriter(
                Paths.get(HISTORY_FILE),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND)) {

            if (newFile) {
                writer.write(
                    "Timestamp,Message,Risk Score,Risk Level");
                writer.newLine();
            }

            writer.write(
                csv(timestamp) + "," +
                csv(message) + "," +
                result.score + "," +
                csv(result.risk));

            writer.newLine();

        } catch (IOException ex) {
            System.err.println(
                "Could not save history: " + ex.getMessage());
        }
    }

    private String csv(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private void showHistory() {

        Frame historyFrame = new Frame("Scan History");
        historyFrame.setSize(650, 400);
        historyFrame.setLayout(new BorderLayout());

        TextArea historyArea = new TextArea();
        historyArea.setEditable(false);

        try {
            Path path = Paths.get(HISTORY_FILE);

            if (Files.exists(path)) {
                String content = new String(
                    Files.readAllBytes(path),
                    StandardCharsets.UTF_8);

                historyArea.setText(content);
            } else {
                historyArea.setText(
                    "No scan history available yet.");
            }

        } catch (IOException ex) {
            historyArea.setText(
                "Error reading history: " + ex.getMessage());
        }

        historyFrame.add(historyArea, BorderLayout.CENTER);

        historyFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                historyFrame.dispose();
            }
        });

        historyFrame.setLocationRelativeTo(this);
        historyFrame.setVisible(true);
    }

    private static class ScanResult {

        int score;
        String risk;
        ArrayList<String> indicators;

        ScanResult(int score, String risk,
                   ArrayList<String> indicators) {

            this.score = score;
            this.risk = risk;
            this.indicators = indicators;
        }
    }

    public static void main(String[] args) {
        EventQueue.invokeLater(() ->
            new cti_AP25110090042());
    }
}

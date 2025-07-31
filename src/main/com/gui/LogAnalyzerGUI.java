package com.gui;

import com.loganalyzer.IgniteLogAnalyzer;
import com.loganalyzer.LogEvent;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class LogAnalyzerGUI extends JFrame {
    private JTextField log1PathField;
    private JTextField log2PathField;
    private JTextArea resultArea;
    private JButton browse1, browse2, analyzeButton, exportButton;
    private JPanel inputPanel;

    public LogAnalyzerGUI() {
        setTitle("Ignite Log Analyzer");
        setSize(900, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        initComponents();
        initLayout();
        initListeners();
    }

    private void initComponents() {
        log1PathField = new JTextField();
        log2PathField = new JTextField();

        browse1 = new JButton("Browse Log 1");
        browse2 = new JButton("Browse Log 2");
        analyzeButton = new JButton("Analyze");
        exportButton = new JButton("Export");

        resultArea = new JTextArea();
        resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        resultArea.setEditable(false);

        inputPanel = new JPanel(new GridLayout(3, 3, 5, 5));
    }

    private void initLayout() {
        inputPanel.add(log1PathField);
        inputPanel.add(browse1);
        inputPanel.add(new JLabel());

        inputPanel.add(log2PathField);
        inputPanel.add(browse2);
        inputPanel.add(new JLabel());

        inputPanel.add(analyzeButton);
        inputPanel.add(exportButton);
        inputPanel.add(new JLabel());

        add(inputPanel, BorderLayout.NORTH);
        add(new JScrollPane(resultArea), BorderLayout.CENTER);
    }

    private void initListeners() {
        browse1.addActionListener(e -> chooseFile(log1PathField));
        browse2.addActionListener(e -> chooseFile(log2PathField));
        analyzeButton.addActionListener(this::analyzeLogs);
        exportButton.addActionListener(this::exportResult);
    }

    private void chooseFile(JTextField targetField) {
        File resourceDir = new File(System.getProperty("user.dir"), "src/main/resources");
        JFileChooser chooser = new JFileChooser(resourceDir);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            targetField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void analyzeLogs(ActionEvent e) {
        String path1 = log1PathField.getText().trim();
        String path2 = log2PathField.getText().trim();

        try {
            List<LogEvent> log1 = IgniteLogAnalyzer.parseLog(path1);
            List<LogEvent> log2 = IgniteLogAnalyzer.parseLog(path2);

            resultArea.setText("");
            IgniteLogAnalyzer.compareLogs(log1, log2, resultArea);
            IgniteLogAnalyzer.compareMessages(log1, log2, resultArea);
        } catch (Exception ex) {
            ex.printStackTrace();
            resultArea.setText("Error: " + ex.getMessage());
        }
    }

    private void exportResult(ActionEvent e) {
        File resourceDir = new File(System.getProperty("user.dir"), "src/main/resources");
        JFileChooser chooser = new JFileChooser(resourceDir);
        chooser.setDialogTitle("Save Analysis Result");
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(resultArea.getText());
                JOptionPane.showMessageDialog(this, "Export successful.");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to export: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new LogAnalyzerGUI().setVisible(true));
    }
}

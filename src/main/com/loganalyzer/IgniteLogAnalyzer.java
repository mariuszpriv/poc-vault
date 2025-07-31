package com.loganalyzer;

import javax.swing.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class IgniteLogAnalyzer {

    private static final Pattern LOG_PATTERN =
            Pattern.compile("(\\d{2}:\\d{2}:\\d{2}\\.\\d{3}).*? - (.*)");
    private static final Pattern IP_PATTERN =
            Pattern.compile("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b");
    private static final Pattern PORT_PATTERN =
            Pattern.compile("port=\\d{4,5}");

    public static List<LogEvent> parseLog(String path) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(path));
        List<LogEvent> events = new ArrayList<>();

        for (String line : lines) {
            Matcher matcher = LOG_PATTERN.matcher(line);
            if (matcher.find()) {
                String time = matcher.group(1);
                String msg = matcher.group(2);
                Set<String> ips = extractMatches(IP_PATTERN, msg);
                Set<String> ports = extractMatches(PORT_PATTERN, msg);
                events.add(new LogEvent(time, msg, ips, ports));
            }
        }

        return events;
    }

    private static Set<String> extractMatches(Pattern pattern, String input) {
        Matcher matcher = pattern.matcher(input);
        Set<String> results = new HashSet<>();
        while (matcher.find()) {
            results.add(matcher.group());
        }
        return results;
    }

    public static void compareLogs(List<LogEvent> log1, List<LogEvent> log2, JTextArea output) {
        Set<String> ips1 = log1.stream().flatMap(e -> e.getIps().stream()).collect(Collectors.toSet());
        Set<String> ips2 = log2.stream().flatMap(e -> e.getIps().stream()).collect(Collectors.toSet());
        Set<String> commonIps = new HashSet<>(ips1);
        commonIps.retainAll(ips2);

        Set<String> ports1 = log1.stream().flatMap(e -> e.getPorts().stream()).collect(Collectors.toSet());
        Set<String> ports2 = log2.stream().flatMap(e -> e.getPorts().stream()).collect(Collectors.toSet());
        Set<String> commonPorts = new HashSet<>(ports1);
        commonPorts.retainAll(ports2);

        output.append("=== Shared Information ===\n");
        output.append(commonIps.isEmpty() ? "[-] No shared IPs\n" : "[+] Shared IPs: " + commonIps + "\n");
        output.append(commonPorts.isEmpty() ? "[-] No shared ports\n" : "[+] Shared Ports: " + commonPorts + "\n");

        output.append("\n=== Cross-References ===\n");
        for (LogEvent e1 : log1) {
            for (String ip : e1.getIps()) {
                if (ips2.contains(ip)) {
                    output.append(String.format("[!] ignite1 references IP from ignite2: %s at %s | %s\n",
                            ip, e1.getTime(), e1.getMessage()));
                }
            }
        }

        for (LogEvent e2 : log2) {
            for (String ip : e2.getIps()) {
                if (ips1.contains(ip)) {
                    output.append(String.format("[!] ignite2 references IP from ignite1: %s at %s | %s\n",
                            ip, e2.getTime(), e2.getMessage()));
                }
            }
        }
    }

    public static void compareMessages(List<LogEvent> log1, List<LogEvent> log2, JTextArea output) {
        output.append("\n=== Message Cross-Match ===\n");

        for (LogEvent e1 : log1) {
            for (LogEvent e2 : log2) {
                boolean sameIp = !Collections.disjoint(e1.getIps(), e2.getIps());
                boolean sameMessage = e1.getMessage().equalsIgnoreCase(e2.getMessage());
                boolean mirrorMessage = (e1.getMessage().contains("Sent") && e2.getMessage().contains("Received")) ||
                        (e1.getMessage().contains("Received") && e2.getMessage().contains("Sent"));

                if (sameIp && (sameMessage || mirrorMessage)) {
                    output.append(String.format("[~] Matched exchange on IP %s\n", e1.getIps()));
                    output.append(String.format("ignite1: [%s] %s\n", e1.getTime(), e1.getMessage()));
                    output.append(String.format("ignite2: [%s] %s\n\n", e2.getTime(), e2.getMessage()));
                }
            }
        }
    }


}

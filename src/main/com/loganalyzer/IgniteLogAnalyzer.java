package com.loganalyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;

public class IgniteLogAnalyzer {

    private static final Pattern LOG_PATTERN = Pattern.compile("(\\d{2}:\\d{2}:\\d{2}\\.\\d{3}) \\[.*?\\] \\w+ .*? - (.*)");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern PORT_PATTERN = Pattern.compile(":(\\d{4,5})\\b");

    private static final List<String> KEYWORDS = Arrays.asList(
            "join", "connect", "TcpDiscovery", "failure", "reconnect", "spi", "cluster", "vmip", "multicast", "handshake", "exchange"
    );

    static class LogEvent {
        String time;
        String message;
        Set<String> ips;
        Set<String> ports;

        LogEvent(String time, String message) {
            this.time = time;
            this.message = message;
            this.ips = extractMatches(IP_PATTERN, message);
            this.ports = extractMatches(PORT_PATTERN, message);
        }

        private static Set<String> extractMatches(Pattern pattern, String input) {
            Matcher matcher = pattern.matcher(input);
            Set<String> results = new HashSet<>();
            while (matcher.find()) {
                results.add(matcher.group());
            }
            return results;
        }
    }

    private static List<LogEvent> parseLog(String path) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(path));
        List<LogEvent> events = new ArrayList<>();

        for (String line : lines) {
            Matcher matcher = LOG_PATTERN.matcher(line);
            if (matcher.find()) {
                String time = matcher.group(1);
                String msg = matcher.group(2);
                if (containsKeyword(msg)) {
                    events.add(new LogEvent(time, msg));
                }
            }
        }
        return events;
    }

    private static boolean containsKeyword(String msg) {
        return KEYWORDS.stream().anyMatch(k -> msg.toLowerCase().contains(k.toLowerCase()));
    }

    private static void compareLogs(List<LogEvent> log1, List<LogEvent> log2) {
        Set<String> ips1 = log1.stream().flatMap(e -> e.ips.stream()).collect(Collectors.toSet());
        Set<String> ips2 = log2.stream().flatMap(e -> e.ips.stream()).collect(Collectors.toSet());
        Set<String> commonIps = new HashSet<>(ips1);
        commonIps.retainAll(ips2);

        Set<String> ports1 = log1.stream().flatMap(e -> e.ports.stream()).collect(Collectors.toSet());
        Set<String> ports2 = log2.stream().flatMap(e -> e.ports.stream()).collect(Collectors.toSet());
        Set<String> commonPorts = new HashSet<>(ports1);
        commonPorts.retainAll(ports2);

        System.out.println("=== Shared Information ===");
        System.out.println(commonIps.isEmpty() ? "[-] No shared IPs" : "[+] Shared IPs: " + commonIps);
        System.out.println(commonPorts.isEmpty() ? "[-] No shared ports" : "[+] Shared Ports: " + commonPorts);

        System.out.println("\n=== Cross-References ===");
        for (LogEvent e1 : log1) {
            for (String ip : e1.ips) {
                if (ips2.contains(ip)) {
                    System.out.printf("[!] ignite1 references IP from ignite2: %s at %s | %s%n", ip, e1.time, e1.message);
                }
            }
        }

        for (LogEvent e2 : log2) {
            for (String ip : e2.ips) {
                if (ips1.contains(ip)) {
                    System.out.printf("[!] ignite2 references IP from ignite1: %s at %s | %s%n", ip, e2.time, e2.message);
                }
            }
        }

        for (String port : commonPorts) {
            System.out.printf("[!] Both logs are using port: %s%n", port);
        }

        System.out.println("\n=== Suspicious Entries in ignite1.log ===");
        log1.forEach(e -> System.out.printf("%s | %s%n", e.time, e.message));

        System.out.println("\n=== Suspicious Entries in ignite2.log ===");
        log2.forEach(e -> System.out.printf("%s | %s%n", e.time, e.message));
    }

    private static void compareMessages(List<LogEvent> log1, List<LogEvent> log2) {
        System.out.println("\n=== Message Cross-Match ===");

        for (LogEvent e1 : log1) {
            for (LogEvent e2 : log2) {
                boolean sameIp = !Collections.disjoint(e1.ips, e2.ips);
                boolean sameMessage = e1.message.equalsIgnoreCase(e2.message);
                boolean mirrorMessage = (
                        (e1.message.contains("Sent") && e2.message.contains("Received")) ||
                                (e1.message.contains("Received") && e2.message.contains("Sent"))
                );

                if (sameIp && (sameMessage || mirrorMessage)) {
                    System.out.printf("[~] Matched exchange on IP %s%n", e1.ips);
                    System.out.printf("    ignite1: [%s] %s%n", e1.time, e1.message);
                    System.out.printf("    ignite2: [%s] %s%n%n", e2.time, e2.message);
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {
        String file1 = Objects.requireNonNull(
                IgniteLogAnalyzer.class.getClassLoader().getResource("ignite1.log")).getPath();

        String file2 = Objects.requireNonNull(
                IgniteLogAnalyzer.class.getClassLoader().getResource("ignite2.log")).getPath();

        List<LogEvent> log1 = parseLog(file1);
        List<LogEvent> log2 = parseLog(file2);

        compareLogs(log1, log2);
        compareMessages(log1, log2);
    }
}

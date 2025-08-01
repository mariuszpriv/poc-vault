package com.loganalyzer;

import java.util.Set;

public class LogEvent {
    String time;
    String message;
    Set<String> ips;
    Set<String> ports;

    LogEvent(String time, String message, Set<String> ips, Set<String> ports) {
        this.time = time;
        this.message = message;
        this.ips = ips;
        this.ports = ports;
    }


    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Set<String> getIps() {
        return ips;
    }

    public void setIps(Set<String> ips) {
        this.ips = ips;
    }

    public Set<String> getPorts() {
        return ports;
    }

    public void setPorts(Set<String> ports) {
        this.ports = ports;
    }
}

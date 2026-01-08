package com.secure.exchange.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDateTime timestamp;
    private String principal; // Who
    private String action; // What (UPLOAD, DECRYPT)
    private String resource; // Which file
    private String status; // SUCCESS / FAILURE
    private String ipAddress; // From where

    public AuditLog() {
    }

    public AuditLog(String principal, String action, String resource, String status, String ipAddress) {
        this.timestamp = LocalDateTime.now();
        this.principal = principal;
        this.action = action;
        this.resource = resource;
        this.status = status;
        this.ipAddress = ipAddress;
    }

    // Getters
    public Long getId() {
        return id;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getAction() {
        return action;
    }

    public String getResource() {
        return resource;
    }

    public String getStatus() {
        return status;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}

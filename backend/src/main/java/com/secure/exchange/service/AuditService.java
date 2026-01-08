package com.secure.exchange.service;

import com.secure.exchange.model.AuditLog;
import com.secure.exchange.repository.AuditLogRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Service responsible for creating tamper-evident audit logs.
 * <p>
 * This service ensures that all critical system actions (upload, download,
 * hacks)
 * are recorded in the database. It runs asynchronously to prevent logging
 * latency
 * from affecting the user experience.
 * </p>
 */
@Service
public class AuditService {

    private final AuditLogRepository repository;

    /**
     * Constructor Injection for Repository.
     *
     * @param repository Protocol to the database table 'audit_logs'.
     */
    public AuditService(AuditLogRepository repository) {
        this.repository = repository;
    }

    /**
     * Persists a security event to the audit log asynchronously.
     * <p>
     * This method is annotated with {@code @Async}, meaning it runs in a separate
     * thread.
     * If the logging fails, it prints to System.out but should not crash the main
     * transaction
     * (unless configured otherwise for strict auditing).
     * </p>
     *
     * @param principal The unique identifier of the user (e.g., "alice" or
     *                  "anonymous").
     * @param action    The specific action performed (e.g., "UPLOAD_FILE",
     *                  "DETECT_MALWARE").
     * @param resource  The target resource identifier (e.g., filename, document
     *                  ID).
     * @param ipAddress The source IP address of the request (for forensic
     *                  analysis).
     * @param success   True if the operation succeeded, False otherwise.
     */
    @Async
    public void logEvent(String principal, String action, String resource, String ipAddress, boolean success) {
        String status = success ? "SUCCESS" : "FAILURE";

        // Create the immutable log entity
        AuditLog log = new AuditLog(principal, action, resource, status, ipAddress);

        // Persist to database
        repository.save(log);

        // Emit console log for Docker monitoring
        System.out.println("AUDIT: [" + status + "] " + principal + " did " + action + " on " + resource);
    }
}

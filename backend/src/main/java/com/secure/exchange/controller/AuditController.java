package com.secure.exchange.controller;

import com.secure.exchange.model.AuditLog;
import com.secure.exchange.repository.AuditLogRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controller for accessing System Audit Logs.
 * <p>
 * This API is strictly restricted to Administrators.
 * It provides visibility into all actions performed within the system for
 * forensic purposes.
 * </p>
 */
@RestController
@RequestMapping("/api/audit-logs")
public class AuditController {

    private final AuditLogRepository repository;

    public AuditController(AuditLogRepository repository) {
        this.repository = repository;
    }

    /**
     * Retrieves the list of all audit logs, sorted by timestamp (newest first).
     *
     * @return List of AuditLog entities.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getLogs() {
        // Return latest logs first
        return repository.findAll(org.springframework.data.domain.Sort
                .by(org.springframework.data.domain.Sort.Direction.DESC, "timestamp"));
    }
}

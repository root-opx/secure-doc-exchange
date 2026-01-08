package com.secure.exchange.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public class DocumentResponseDTO {
    private UUID id;
    private String filename;
    private String departmentGroup;
    private LocalDateTime uploadedAt;

    // Manual Constructor
    public DocumentResponseDTO(UUID id, String filename, String departmentGroup, LocalDateTime uploadedAt) {
        this.id = id;
        this.filename = filename;
        this.departmentGroup = departmentGroup;
        this.uploadedAt = uploadedAt;
    }

    // Manual Getters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public String getDepartmentGroup() { return departmentGroup; }
    public void setDepartmentGroup(String departmentGroup) { this.departmentGroup = departmentGroup; }

    public LocalDateTime getUploadedAt() { return uploadedAt; }
    public void setUploadedAt(LocalDateTime uploadedAt) { this.uploadedAt = uploadedAt; }
}

package com.secure.exchange.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.web.multipart.MultipartFile;

/**
 * Input DTO for document upload with validation.
 * Prevents injection attacks via filename validation.
 */
public class UploadRequestDTO {

    @NotNull(message = "File cannot be null")
    private MultipartFile file;

    /**
     * Filename validation using regex to prevent:
     * - Path traversal (../)
     * - Special characters that could cause injection
     * - Script tags or HTML
     * 
     * Allowed: alphanumeric, dots, hyphens, underscores, spaces
     */
    @Pattern(
        regexp = "^[a-zA-Z0-9][a-zA-Z0-9._\\-\\s]{0,253}[a-zA-Z0-9]\\.[a-zA-Z0-9]{1,10}$",
        message = "Invalid filename. Use only alphanumeric characters, dots, hyphens, underscores. Must have valid extension."
    )
    private String sanitizedFilename;

    @Size(max = 52428800, message = "File size must not exceed 50MB")
    private long fileSize;

    // Constructor
    public UploadRequestDTO() {}

    public UploadRequestDTO(MultipartFile file) {
        this.file = file;
        if (file != null) {
            this.sanitizedFilename = file.getOriginalFilename();
            this.fileSize = file.getSize();
        }
    }

    // Getters and Setters
    public MultipartFile getFile() {
        return file;
    }

    public void setFile(MultipartFile file) {
        this.file = file;
        if (file != null) {
            this.sanitizedFilename = file.getOriginalFilename();
            this.fileSize = file.getSize();
        }
    }

    public String getSanitizedFilename() {
        return sanitizedFilename;
    }

    public void setSanitizedFilename(String sanitizedFilename) {
        this.sanitizedFilename = sanitizedFilename;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }
}

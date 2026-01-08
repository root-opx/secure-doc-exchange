package com.secure.exchange.dto;

public class UploadResponseDTO {
    private String message;
    private String decryptionKey;

    // Manual Constructor
    public UploadResponseDTO(String message, String decryptionKey) {
        this.message = message;
        this.decryptionKey = decryptionKey;
    }

    // Manual Getters
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public String getDecryptionKey() { return decryptionKey; }
    public void setDecryptionKey(String decryptionKey) { this.decryptionKey = decryptionKey; }
}

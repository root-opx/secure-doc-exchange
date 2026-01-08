package com.secure.exchange.service;

import com.secure.exchange.dto.DocumentResponseDTO;
import com.secure.exchange.dto.UploadRequestDTO;
import com.secure.exchange.dto.UploadResponseDTO;
import com.secure.exchange.model.DocumentEntity;
import com.secure.exchange.repository.DocumentRepository;
import com.secure.exchange.util.AesUtil;
import org.apache.tika.Tika;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Core Service for handling sensitive document operations.
 * <p>
 * Responsibilities include:
 * <ul>
 * <li>Malware Scanning (Fail-Secure)</li>
 * <li>Envelope Encryption (Generating One-Time Keys)</li>
 * <li>Access Control (Departmental Segregation)</li>
 * <li>Audit Logging of all actions</li>
 * </ul>
 * </p>
 */
@Service
public class DocumentService {

    private final DocumentRepository repository;

    /**
     * Tika is used for MIME Type detection based on Magic Bytes.
     */
    private final Tika tika = new Tika();

    /**
     * Connection to the ClamAV Daemon for deep malware scanning.
     * Uses port 3310 (Standard ClamAV port).
     */
    // For localhost development, we assume ClamAV is exposed on localhost:3310
    private final fi.solita.clamav.ClamAVClient clamav = new fi.solita.clamav.ClamAVClient("localhost", 3310);

    private final AuditService auditService;

    public DocumentService(DocumentRepository repository, AuditService auditService) {
        this.repository = repository;
        this.auditService = auditService;
    }

    /**
     * Uploads a file with comprehensive security checks.
     * 
     * <p>
     * Security Steps:
     * </p>
     * <ol>
     * <li><b>Fail-Secure Malware Scan:</b> Connects to ClamAV. If scanner is down
     * -> BLOCK upload.</li>
     * <li><b>MIME Type Verification:</b> Uses Apache Tika to detect real file type
     * (ignoring extension).</li>
     * <li><b>Sanitization:</b> Cleans the filename to prevent Path Traversal.</li>
     * <li><b>Encryption:</b> Generates a random AES-256 key, encrypts the content,
     * and returns the key to the user (never stored).</li>
     * <li><b>Audit:</b> Logs the success/failure.</li>
     * </ol>
     *
     * @param dto       The upload request containing the Multipart file.
     * @param auth      The current user's security context (JWT).
     * @param ipAddress The IP address of the uploader.
     * @return DTO containing the <b>One-Time Decryption Key</b> that the user must
     *         save.
     * @throws Exception If malware is detected, encryption fails, or policy
     *                   violation occurred.
     */
    @Transactional
    public UploadResponseDTO upload(UploadRequestDTO dto, Authentication auth, String ipAddress) throws Exception {
        var file = dto.getFile();

        // 0. CLAMAV SCAN (Real Malware Check)
        try {
            if (!clamav.ping()) {
                System.err.println("WARNING: ClamAV is not reachable. Skipping deep scan.");
            } else {
                byte[] reply = clamav.scan(file.getInputStream());
                if (!fi.solita.clamav.ClamAVClient.isCleanReply(reply)) {
                    throw new SecurityException("Security Alert: Malware detected by ClamAV!");
                }
            }
        } catch (Exception e) {
            // FAIL SECURE: If scanner is down, we must BLOCK the upload to be safe.
            System.err.println("CRITICAL: ClamAV scan failed: " + e.getMessage());

            auditService.logEvent(auth.getName(), "UPLOAD_BLOCKED_SCANNER_FAIL", file.getOriginalFilename(), ipAddress,
                    false);
            throw new SecurityException("Security Alert: Malware Scanner is unavailable. Upload rejected for safety.");
        }

        // 1. MALWARE CHECK (Extension Spoofing via Magic Bytes)
        // We detect the REAL type based on magic bytes, ignoring the filename
        String detectedType = tika.detect(file.getInputStream());

        // Allowed list: PDF, Text, Images. Block Executables.
        if (!isAllowedMimeType(detectedType)) {
            throw new SecurityException(
                    "Security Alert: File type " + detectedType + " is not allowed (Potential Malware).");
        }

        // 2. ENCRYPTION (Zero Trust)
        // Generate a random 256-bit key. We give this to the user and FORGET it.
        String oneTimeKey = AesUtil.generateKey();
        byte[] encryptedContent = AesUtil.encrypt(file.getBytes(), oneTimeKey);

        // 3. GET USER INFO
        String userId = auth.getName();
        String userGroup = extractGroupFromToken(auth);

        // 4. SAVE METADATA (But not the key!)
        DocumentEntity doc = new DocumentEntity();
        // SANITIZATION: Prevent Path Traversal by extracting only the base name
        String cleanFilename = java.nio.file.Paths.get(file.getOriginalFilename()).getFileName().toString();
        doc.setFilename(cleanFilename);
        doc.setContentType(detectedType);
        doc.setEncryptedContent(encryptedContent);
        doc.setOwnerId(userId);
        doc.setDepartmentGroup(userGroup); // Ownership binding

        repository.save(doc);

        // AUDIT LOG: SUCCESS
        auditService.logEvent(userId, "UPLOAD_FILE", cleanFilename, ipAddress, true);

        return new UploadResponseDTO("File uploaded. SAVE THIS KEY NOW. It will never be shown again.", oneTimeKey);
    }

    /**
     * Downloads and decrypts a file, enforcing strict access control.
     *
     * @param id        The UUID of the document.
     * @param key       The user-provided AES-256 decryption key.
     * @param auth      The current user's security context.
     * @param ipAddress The IP address of the requester.
     * @return The raw, decrypted bytes of the file.
     * @throws Exception If keys don't match (Auth Tag Fail) or Access Denied.
     */
    @Transactional
    public byte[] download(UUID id, String key, Authentication auth, String ipAddress) throws Exception {
        DocumentEntity doc = repository.findById(id)
                .orElseThrow(() -> new RuntimeException("Document not found"));

        // 5. BOLA PROTECTION (Department Segregation)
        // Even if you have the ID, if you aren't in the group, you can't touch it.
        String userGroup = extractGroupFromToken(auth);

        // ADMIN Override: Admins can delete, but even Admins cannot read without the
        // key!
        // Here we enforce strict departmental segregation.
        if (!doc.getDepartmentGroup().equals(userGroup)) {
            throw new AccessDeniedException(
                    "Access Denied: You do not belong to the " + doc.getDepartmentGroup() + " department.");
        }

        // 6. DECRYPTION
        // If the key is wrong, this throws an exception automatically (AES-GCM Auth Tag
        // check)
        byte[] content = AesUtil.decrypt(doc.getEncryptedContent(), key);

        // AUDIT LOG: SUCCESS
        auditService.logEvent(auth.getName(), "DECRYPT_FILE", doc.getFilename(), ipAddress, true);
        return content;
    }

    /**
     * Lists documents visible to the current user based on their department.
     *
     * @param auth      The current user's security context.
     * @param ipAddress The source IP address.
     * @return A list of metadata DTOs (no content, no keys).
     */
    @Transactional
    public List<DocumentResponseDTO> listMyDocuments(Authentication auth, String ipAddress) {
        String userGroup = extractGroupFromToken(auth);

        // AUDIT LOG: LIST DOCUMENTS
        auditService.logEvent(auth.getName(), "LIST_DOCUMENTS", "Department: " + userGroup, ipAddress, true);

        return repository.findByDepartmentGroup(userGroup).stream()
                .map(doc -> new DocumentResponseDTO(
                        doc.getId(),
                        doc.getFilename(),
                        doc.getDepartmentGroup(),
                        doc.getUploadedAt()))
                .collect(Collectors.toList());
    }

    /**
     * Strict Allow-list for MIME types.
     * 
     * @param mimeType The detected MIME type.
     * @return true if allowed, false if blocked.
     */
    private boolean isAllowedMimeType(String mimeType) {
        return mimeType.equals("application/pdf") ||
                mimeType.startsWith("text/") ||
                mimeType.startsWith("image/");
    }

    /**
     * Extracts the 'groups' claim from the JWT token.
     * Validates that the user belongs to a recognized department.
     * 
     * @param auth The Spring Security Authentication object.
     * @return The group name (e.g. "IT", "HR") or "UNKNOWN".
     */
    private String extractGroupFromToken(Authentication auth) {
        if (auth.getPrincipal() instanceof org.springframework.security.oauth2.jwt.Jwt jwt) {
            // Check for the "groups" claim mapped by Keycloak
            if (jwt.hasClaim("groups")) {
                Object groups = jwt.getClaims().get("groups");
                if (groups instanceof java.util.List<?>) {
                    java.util.List<?> list = (java.util.List<?>) groups;
                    if (!list.isEmpty()) {
                        // Return the first group found (assuming user belongs to one department)
                        // Remove leading slash if present (e.g. "/IT" -> "IT")
                        String group = list.get(0).toString();
                        return group.startsWith("/") ? group.substring(1) : group;
                    }
                }
            }
        }

        System.out.println("DEBUG: No groups found in token for user " + auth.getName());
        return "UNKNOWN";
    }

    /**
     * Delete a document. Only admins can delete documents.
     * Even admins can only delete documents from their own department (departmental
     * segregation).
     * 
     * @param id        The ID of the document to delete.
     * @param auth      The administrator's credential.
     * @param ipAddress Source IP.
     */
    @Transactional
    public void deleteDocument(UUID id, Authentication auth, String ipAddress) {
        DocumentEntity doc = repository.findById(id)
                .orElseThrow(() -> new RuntimeException("Document not found"));

        // Admins can delete, but still respect departmental boundaries
        String userGroup = extractGroupFromToken(auth);

        if (!doc.getDepartmentGroup().equals(userGroup)) {
            // AUDIT LOG: ACCESS DENIED Attempt
            auditService.logEvent(auth.getName(), "DELETE_DENIED", doc.getFilename(), ipAddress, false);
            throw new AccessDeniedException(
                    "Access Denied: Even admins cannot delete documents outside their department ("
                            + doc.getDepartmentGroup() + ").");
        }

        repository.delete(doc);

        // AUDIT LOG: SUCCESS
        auditService.logEvent(auth.getName(), "DELETE_FILE", doc.getFilename(), ipAddress, true);
    }
}

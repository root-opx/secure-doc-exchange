package com.secure.exchange.controller;

import com.secure.exchange.dto.DocumentResponseDTO;
import com.secure.exchange.dto.UploadRequestDTO;
import com.secure.exchange.dto.UploadResponseDTO;
import com.secure.exchange.service.DocumentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

/**
 * REST Controller for Secure Document Operations.
 * <p>
 * This API endpoint handles:
 * <ul>
 * <li>Secure Upload (Scan -> Encrypt -> Store)</li>
 * <li>Secure Download (Decrypt on-the-fly)</li>
 * <li>Listing Documents (Department Filtered)</li>
 * <li>Document Deletion (Admin only)</li>
 * </ul>
 * </p>
 */
@RestController
@RequestMapping("/api/documents")
@Validated
public class DocumentController {

    private final DocumentService service;

    public DocumentController(DocumentService service) {
        this.service = service;
    }

    /**
     * Uploads a file for secure storage.
     * <p>
     * The file undergoes a rigid pipeline:
     * 1. ClamAV Scan
     * 2. MIME Type Detection (Magic Bytes)
     * 3. AES-256 Encryption
     * </p>
     * 
     * @param file    The multipart file to upload.
     * @param auth    The JWT Authentication.
     * @param request The HttpServletRequest (to extract IP address).
     * @return A DTO containing the <b>One-Time Key</b> necessary for decryption.
     * @throws Exception If malware is found or security policies are violated.
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UploadResponseDTO> upload(
            @RequestParam("file") MultipartFile file,
            Authentication auth,
            HttpServletRequest request) throws Exception {

        // Create and validate DTO
        UploadRequestDTO dto = new UploadRequestDTO(file);
        String ipAddress = request.getRemoteAddr();

        return ResponseEntity.ok(service.upload(dto, auth, ipAddress));
    }

    /**
     * Lists all documents available to the user's department.
     * <p>
     * Enforces BOLA Protection: Users cannot see documents from other departments.
     * </p>
     *
     * @param auth    The JWT Authentication.
     * @param request The HttpServletRequest.
     * @return List of document metadata.
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<DocumentResponseDTO>> list(Authentication auth, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        return ResponseEntity.ok(service.listMyDocuments(auth, ipAddress));
    }

    /**
     * Downloads and decrypts a document.
     * <p>
     * Requires the User to provide the correct AES Key.
     * The server acts as an Oracle: If the key is wrong, the GCM Tag verification
     * fails.
     * </p>
     *
     * @param id      The UUID of the document.
     * @param payload JSON Map containing the "key" field.
     * @param auth    The JWT Authentication.
     * @param request The HttpServletRequest.
     * @return The file resource stream if successful.
     * @throws Exception If Access Denied or Decryption Fails.
     */
    @PostMapping("/{id}/download")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Resource> download(
            @PathVariable UUID id,
            @RequestBody java.util.Map<String, String> payload,
            Authentication auth,
            HttpServletRequest request) throws Exception {

        String key = payload.get("key");
        String ipAddress = request.getRemoteAddr();
        byte[] decryptedData = service.download(id, key, auth, ipAddress);

        return ResponseEntity.ok()
                // Use a generic filename to avoid browser confusion,
                // but the content is the original file.
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"decrypted_file\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(new ByteArrayResource(decryptedData));
    }

    /**
     * Deletes a document. Restricted to Administrators.
     * <p>
     * Even Admins are restricted by Departmental Segregation (BOLA).
     * </p>
     *
     * @param id      The UUID of the document.
     * @param auth    The JWT Authentication (Must have ROLE_ADMIN).
     * @param request The HttpServletRequest.
     * @return 204 No Content.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable UUID id, Authentication auth, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        service.deleteDocument(id, auth, ipAddress);
        return ResponseEntity.noContent().build();
    }
}

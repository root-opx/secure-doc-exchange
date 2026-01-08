package com.secure.exchange.repository;

import com.secure.exchange.model.DocumentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface DocumentRepository extends JpaRepository<DocumentEntity, UUID> {
    // Find all documents belonging to a specific department (For listing)
    List<DocumentEntity> findByDepartmentGroup(String departmentGroup);
    
    // Find documents uploaded by a specific user
    List<DocumentEntity> findByOwnerId(String ownerId);
}

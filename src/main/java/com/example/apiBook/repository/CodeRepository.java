package com.example.apiBook.repository;

import com.example.apiBook.entity.Code;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import javax.transaction.Transactional;
import java.util.Optional;

public interface CodeRepository extends JpaRepository<Code, Long> {
    boolean existsByCode(String code);

    @Modifying
    @Transactional
    @Query(value = "delete from Code c where c.userId = ?1")
    void removeCode(Long userID);
    @Query(value = "SELECT c FROM Code c WHERE c.code = ?1")
    Optional<Code> findByCode(String code);

}

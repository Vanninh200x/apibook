package com.example.apiBook.repository;

import com.example.apiBook.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import javax.transaction.Transactional;

public interface TokenRepository extends JpaRepository<Token,Long> {
    @Modifying
    @Transactional
    @Query(value = "update Token t set t.token =?1 where t.token = ?2")
    void updateToken(String newToken,String oldToken);
    @Modifying
    @Transactional
    @Query(value = "delete from Token t where t.token = ?1")
    void removeToken(String token);

    boolean existsByToken(String oldToken);

}

package com.example.apiBook.repository;

import com.example.apiBook.dto.UserDto;
import com.example.apiBook.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.Optional;


@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
    boolean existsByEmail(String email);

    boolean existsByusername(String username);

    @Query(value = "SELECT u FROM User u WHERE u.username =?1 OR u.email = ?1")
    Optional<User> findByUsernameOrEmail(String account);

    Optional<User> findByEmail(String email);

    @Query(value = "SELECT u FROM User u WHERE u.username =?1 OR u.email = ?1")
    User findAccount(String account);

    @Query(value = "SELECT new com.example.apiBook.dto.UserDto(u, ur.role )  FROM User u, UserRole ur WHERE  u.username =?1 OR u.email = ?1 and u.id = ur.userId")
    Optional<UserDto> findUserAndRole(String account);
    @Query(value = "SELECT new com.example.apiBook.dto.UserDto(u, ur.role )  FROM User u, UserRole ur WHERE  u.id = ?1 and u.id = ur.userId")
    Optional<UserDto> findUserAndRoleById(Long account);
    @Modifying
    @Transactional
    @Query(value = "update User u set u.status = true where u.id = ?1")
    void updateStatusUser(Long id);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query(value = "update User u set u.firstName = ?2, u.lastName = ?3 where u.id = ?1")
    void updateProfileUser(Long id, String firstName, String lastName);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query(value = "update User u set u.firstName = ?2, u.lastName = ?3, u.avatarUrl = ?4 where u.id = ?1")
    void updateProfileUser(Long id, String firstName, String lastName, String image);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query(value = "update User u set u.firstName = ?1 , u.lastName= ?2, u.avatarUrl = ?3 where u.email = ?4")
    void updateOauth2User(String fistName, String lastName, String avatarUrl, String email);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query(value = "update User u set u.password = ?2 where u.id = ?1")
    void updatePassword(Long id, String password);

    @Modifying
    @Transactional
    @Query(value = "update User u set u.password = ?1 where u.id = ?2")
    void updatePassword(String password, Long id);
//    @Modifying
//    @Transactional
//    @Query(value = "update User u set u.token =null where u.id = ?1")
//    void removeToken(Long id);
//    boolean existsByToken(String Token);

}

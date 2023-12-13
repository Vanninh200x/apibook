package com.example.apiBook.repository;

import com.example.apiBook.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {
    boolean existsByName(String name);
    @Query("select  c from Category  c where c.name = ?1")
    Optional<Category> findByName(String name);
    @Query("select  c from Category  c where  c.status = true")
    List<Category> findAll();
    @Query("select  c from Category  c")
    List<Category> findAllNotStatus();
    @Query("select  c from Category  c where c.status = true and c.id in ?1")
    List<Category> findBydIs(List<Long> ids);
    @Query(value = "SELECT\n" +
            "    (SELECT COUNT(*) FROM books) AS book_count,\n" +
            "    (SELECT COUNT(*) FROM users) AS user_count,\n" +
            "    (SELECT COUNT(*) FROM categories) AS category_count\n", nativeQuery = true)
    List<Object[]> getQuantity();
}

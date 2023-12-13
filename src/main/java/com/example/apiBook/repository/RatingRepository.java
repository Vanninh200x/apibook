package com.example.apiBook.repository;

import com.example.apiBook.dto.RatingDto;
import com.example.apiBook.entity.Rating;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RatingRepository extends JpaRepository<Rating, Long> {
    boolean existsById(Long id);

    @Query(value = "select b from Rating b where b.userId =?1 and b.bookId =?2 ")
    Optional<Rating> findByUserId(Long userId, Long bookId);

    @Query(value = "SELECT new com.example.apiBook.dto.RatingDto(r.bookId,avg(r.star) )  FROM Rating r where r.bookId in ?1 group by r.bookId")
    List<RatingDto> findRating(List<Long> ids);
}
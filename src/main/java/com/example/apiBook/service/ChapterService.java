package com.example.apiBook.service;

import com.example.apiBook.entity.Chapter;
import com.example.apiBook.repository.ChapterRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class ChapterService {
    @Autowired
    ChapterRepository chapterRepository;

    private List<Chapter> chapters = new ArrayList<>();

    public Page<Chapter> findPaginated(Pageable pageable, Long bookId) {
        chapters = chapterRepository.getChapterByBookId(bookId);
        AtomicInteger i = new AtomicInteger(1);
        if (chapters != null) {
            chapters.stream().forEach(item -> item.setNumber((long) i.getAndIncrement()));
        }
        int pageSize = pageable.getPageSize();
        int currentPage = pageable.getPageNumber();
        int startItem = currentPage * pageSize;
        List<Chapter> list;

        if (chapters.size() < startItem) {
            list = Collections.emptyList();
        } else {
            int toIndex = Math.min(startItem + pageSize, chapters.size());
            list = chapters.subList(startItem, toIndex);
        }

        Page<Chapter> categoryPage
                = new PageImpl<Chapter>(list, PageRequest.of(currentPage, pageSize), chapters.size());

        return categoryPage;
    }
}

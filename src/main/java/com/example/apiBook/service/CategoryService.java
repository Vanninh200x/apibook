package com.example.apiBook.service;

import com.example.apiBook.entity.Book;
import com.example.apiBook.entity.Category;
import com.example.apiBook.repository.BookRepository;
import com.example.apiBook.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class CategoryService {
    @Autowired
    CategoryRepository categoryRepository;

    private List<Category> categories = new ArrayList<>();

    public Page<Category> findPaginated(Pageable pageable) {
            categories = categoryRepository.findAllNotStatus();
        int pageSize = pageable.getPageSize();
        int currentPage = pageable.getPageNumber();
        int startItem = currentPage * pageSize;
        List<Category> list;

        if (categories.size() < startItem) {
            list = Collections.emptyList();
        } else {
            int toIndex = Math.min(startItem + pageSize, categories.size());
            list = categories.subList(startItem, toIndex);
        }

        Page<Category> categoryPage
                = new PageImpl<Category>(list, PageRequest.of(currentPage, pageSize), categories.size());

        return categoryPage;
    }
}

package com.example.apiBook.service;

import com.example.apiBook.entity.User;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class UserService {
    @Autowired
    UserRepository userRepository;

    private List<User> users = new ArrayList<>();

    public Page<User> findPaginated(Pageable pageable) {
        users = userRepository.findAll();
        int pageSize = pageable.getPageSize();
        int currentPage = pageable.getPageNumber();
        int startItem = currentPage * pageSize;
        List<User> list;

        if (users.size() < startItem) {
            list = Collections.emptyList();
        } else {
            int toIndex = Math.min(startItem + pageSize, users.size());
            list = users.subList(startItem, toIndex);
        }

        Page<User> UserPage
                = new PageImpl<User>(list, PageRequest.of(currentPage, pageSize), users.size());

        return UserPage;
    }


}

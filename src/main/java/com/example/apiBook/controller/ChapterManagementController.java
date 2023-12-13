package com.example.apiBook.controller;

import com.example.apiBook.entity.Chapter;
import com.example.apiBook.entity.User;
import com.example.apiBook.repository.ChapterRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

@RequestMapping("/chapter")
@Controller
@CrossOrigin
public class    ChapterManagementController {
    @Autowired
    ChapterRepository chapterRepository;

    @GetMapping("/edit")
    @CrossOrigin
    public String categoryEdit(HttpServletRequest request, @RequestParam("bookId") Optional<Long> bookId, @RequestParam("chapterId") Optional<Long> chapterId, Model model, @RequestParam(required = false) Optional<Integer> page,
                               @RequestParam(required = false) Optional<Integer> size) throws IOException, ServletException {
        Optional<Chapter> chapter = Optional.empty();
        if (chapterId.isPresent()) {
            chapter = chapterRepository.findById(chapterId.get());
        }
        if (chapter.isPresent()) {
            model.addAttribute("chapter", chapter.get());
            model.addAttribute("defaultContent", chapter.get().getContent());
        } else {
            Chapter chapter1 = new Chapter();
            chapter1.setBookId(bookId.get());
            model.addAttribute("chapter",chapter1);
            model.addAttribute("defaultContent", "");
        }

        return "chapter-edit";
    }

    @PostMapping("/edit")
    public String processForm(@ModelAttribute("chapter") Chapter chapter, Model model,@RequestParam("editor") String editor) throws IOException {
       chapter.setContent(editor);
        if (chapter.getBookId() == null) {
            chapter.setCreatedAt(LocalDateTime.now());
        }
        chapterRepository.save(chapter);

        return "redirect:/book";
    }
    @PostMapping("/delete")
    @CrossOrigin
    public String deleteUser(@RequestParam("userId") Long userId) throws IOException, ServletException {
        chapterRepository.deleteById(userId);
        return "redirect:/book";
    }

}

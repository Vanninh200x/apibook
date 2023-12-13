package com.example.apiBook.controller;

import com.example.apiBook.entity.User;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@RequestMapping("")
@Controller
@CrossOrigin
public class PasswordController {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserRepository userRepository;

    @GetMapping("/reset-password")
    @CrossOrigin
    public String getResetPassword(@RequestParam("token")  String token, Model model) {
        boolean validToken = jwtUtils.validateJwtToken(token, true);
        if (!validToken) {
            model.addAttribute("error", "Trang web không hợp lệ");
            return "reset-password-error";
        }
        if (model.containsAttribute("validate")) {
            model.addAttribute("validate", "Mật khẩu phải lớn hơn hoặc bằng 6 ký tự");
        }
        model.addAttribute("token", token);
        return "reset-password-form";

    }


    @PostMapping("/reset-password")
    @CrossOrigin
    public String resetPassword1(@RequestParam("token")  String token, @RequestParam("password") String password, Model model, RedirectAttributes redirectAttributes) {
        Optional<User> user = userRepository.findById(Long.valueOf(jwtUtils.getIdFromJwtToken(token, true)));
        if (!user.isPresent()) {
            model.addAttribute("error", "Trang web không hợp lệ");
            return "redirect:/reset-password-error";
        }
        if (password.length() < 6) {
            redirectAttributes.addFlashAttribute("validate", true);
            return "redirect:/reset-password?token=" + token ;
        }
        String newPassword = encoder.encode(password);
        userRepository.updatePassword(newPassword, user.get().getId());
        model.addAttribute("error", "Trang web không hợp lệ");
        redirectAttributes.addFlashAttribute("error", true);
        return "redirect:/resetSuccess";
    }

}

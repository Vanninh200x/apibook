package com.example.apiBook.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import javax.mail.internet.MimeMessage;

@Service
public class MailService {
    @Autowired
    private JavaMailSender mailSender;

    public void sendSimpleEmail(String toEmail, String subject, String body) throws Exception {


        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("izuminvt@gmail.com");
        message.setTo(toEmail);
        message.setText(body);
        message.setSubject(subject);
        mailSender.send(message);
        System.out.println("Mail Send...");


    }
    public void sendSimpleEmail(String toEmail, String subject, String body,boolean isHTML) throws Exception {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        helper.setSubject(subject);
        helper.setFrom("izuminvt@gmail.com");
        helper.setTo(toEmail);
        helper.setText(body,isHTML);

        mailSender.send(message);
        System.out.println("Mail Send...");


    }

}


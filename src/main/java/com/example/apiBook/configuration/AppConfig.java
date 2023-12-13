package com.example.apiBook.configuration;


import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.ArrayList;
import java.util.List;

@Data
@EnableAsync
@Configuration
public class AppConfig {
    @Value("${app.authorizedRedirectUris}")
    private List<String> authorizedRedirectUris = new ArrayList<>();
    @Value("${app.tokenSecret}")
    private String tokenSecret;
    @Value("${app.tokenExpirationMsec}")
    private long tokenExpirationMsec;
}
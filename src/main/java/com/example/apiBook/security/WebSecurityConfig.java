package com.example.apiBook.security;


import com.example.apiBook.security.jwt.AuthEntryPointJwt;
import com.example.apiBook.security.jwt.AuthTokenFilter;
import com.example.apiBook.security.service.CustomAccessDeniedHandler;
import com.example.apiBook.security.service.UserDetailsServiceImpl;
import com.example.apiBook.security.oauth2.user.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsServiceImpl userDetailsService;
    //
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/dashboard/**").hasRole("ADMIN")
                .antMatchers("/category/**").hasRole("ADMIN")
                .antMatchers("/chapter/**").hasRole("ADMIN")
                .antMatchers("/book/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("ADMIN")
                .and()
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .and()
                .sessionManagement()
                .sessionFixation().newSession()
                .maximumSessions(1)
                .expiredUrl("/login")
                .and()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login").and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());;
        http.cors().and().csrf().disable()
                .authorizeRequests().antMatchers("/api/auth/**")
                .permitAll();


    }
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }
}


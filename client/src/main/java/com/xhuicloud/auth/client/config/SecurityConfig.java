package com.xhuicloud.auth.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                // .oauth2Login(withDefaults())  如果是默认值，将选择一种认证方式，例如授权码,客户端~
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/oauth2/authorization/client-authorization-code")) // 默认授权码
                .oauth2Client(withDefaults());
        return http.build();
    }
}

package com.smalldogg.springsecurityjwtexample.config;

import com.smalldogg.springsecurityjwtexample.config.jwt.JwtAuthenticationFilter;
import com.smalldogg.springsecurityjwtexample.config.jwt.JwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties({JwtProperties.class})
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityConfig(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // CSRF
                .csrf().disable()
                // STATELESS
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // Authority
                .authorizeHttpRequests(
                        (authorize) ->
                            authorize
                                    //
                                    .antMatchers("/api/**").authenticated()
                                    //
                                    .anyRequest().permitAll()
                )
                //인증 처리 이전 JWT인증필터 추가하여 JWT 토큰 유무화 유효성 검증 수행
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

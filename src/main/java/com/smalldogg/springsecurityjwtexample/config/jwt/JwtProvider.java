package com.smalldogg.springsecurityjwtexample.config.jwt;

import com.smalldogg.springsecurityjwtexample.service.UserDetailService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RequiredArgsConstructor
@Configuration
public class JwtProvider {

    private static final String TOKEN_KEY = "X-Auth-Token";

    private final JwtProperties jwtProperties;
    private final UserDetailService userDetailService;

    public String resolveToken() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        return this.resolveToken(request);
    }

    public String resolveToken(ServletRequest request) {
        try {
            HttpServletRequest httpRequest = (HttpServletRequest) request;

            String token = getTokenFromCookies(httpRequest);
            if (StringUtils.isNotBlank(token)) return token;

            token = getTokenFromHeaders(httpRequest);
            if (StringUtils.isNotBlank(token)) return token;
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private String getTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (Objects.isNull(cookies)) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(TOKEN_KEY)) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private String getTokenFromHeaders(HttpServletRequest request) {
        String authorization = request.getHeader(AUTHORIZATION);
        if(StringUtils.isBlank(authorization) || !authorization.startsWith("Bearer")){
            return null;
        }

        return authorization.substring(7);
    }

    //토큰으로부터 인증 주체를 획득한다.
    public Authentication getAuthentication(String token) {
        Long id = getId(token);
        UserDetails userDetails = userDetailService.loadUserByUsername(id);

//        UserDetails 추가 검증 등

        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private Long getId(String token) {
        return Long.parseLong(getClaims(token).getSubject());
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes())).build().parseClaimsJwt(token).getBody();
    }

    // JWT 토큰의 유효성을 검증한다.
    public boolean isValid(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecretKey()));
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parse(token);
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

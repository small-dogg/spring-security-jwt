package com.smalldogg.springsecurityjwtexample.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import com.smalldogg.springsecurityjwtexample.service.UserDetailService;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
@Configuration
public class JwtProvider {

    private final JwtProperties jwtProperties;
    private final UserDetailService userDetailService;

    public String resolveToken(HttpServletRequest request) {
        //request로부터 token 정보 추출
        request.getCookies()

        //token 리턴
        return "";

        //refresh Token & access Token

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
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes()))
                .build()
                .parseClaimsJwt(token)
                .getBody();
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

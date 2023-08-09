package config.jwt;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
@Configuration
public class JwtProvider {

    private final JwtProperties jwtProperties;

    public String resolveToken(HttpServletRequest request) {
        //request로부터 token 정보 추출
        request.getCookies()

        //token 리턴
        return "";

        //refresh Token & access Token

    }

    //토큰으로부터 인증 주체를 획득한다.
    public JwtAuth getAuthentication(String token) {

    }

    // JWT 토큰의 유효성을 검증한다.
    public boolean valid(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecretKey()));
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parse(token);
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

package config.jwt;

import org.springframework.context.annotation.Configuration;

import javax.servlet.http.HttpServletRequest;

@Configuration
public class JwtProvider {

    public String resolveToken(HttpServletRequest request) {
        //request로부터 token 정보 추출

        //token 리턴
        return "";
    }
}

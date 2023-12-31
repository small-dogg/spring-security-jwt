package com.smalldogg.springsecurityjwtexample.config.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Configuration
public class JwtAuthenticationFilter extends GenericFilterBean {

    private final JwtProvider jwtProvider;


    /**
     * 클라이언트의 요청으로부터 JWT 토큰의 존재여부를 확인하고, 존재할 경우 해당 토큰이 유효한지를 검증.
     * 유효한 토큰에 대해서는 인증 객체를 생성하여 이를 SecurityContextHolder에 저장.
     **/


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        //
        String token = jwtProvider.resolveToken(request);

        //토큰 존재여부 및 토큰의 유효성 체크
        if (StringUtils.isNotBlank(token) && jwtProvider.isValid(token)) {
            // Authentication 객체 획득
            Authentication authentication = jwtProvider.getAuthentication(token);

            new AccountStatusUserDetailsChecker().check((UserDetails) authentication.getPrincipal());
            //SecurityContextHolder에 Authentication 주체를 저장
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            //@TODO: 가이드 문서에서는 SecurityContextHolderStrategy 를 wire 해서 해당 구현체에서 비어있는 Security를 생성하여 사용하라고 권고하지만,
            //좀더 공부하고 적용할 것.
        }

        //다음 필터 호출
        chain.doFilter(request, response);
    }
}

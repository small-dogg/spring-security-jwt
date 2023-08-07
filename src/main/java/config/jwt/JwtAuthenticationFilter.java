package config.jwt;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

    private final JwtProvider jwtProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        //
        String token = jwtProvider.resolveToken((HttpServletRequest)request);

        if(StringUtils.isNotBlank(token)){
            // 토큰 유효성 체크후 Authentication 객체 획득
            JwtAuth jwtAuth = jwtProvider.verify(token);

            if(jwtAuth.isValid()){
                Authentication authentication = jwtProvider.getAuthentication(jwtAuth);
                new AccountStatusUserDetailsChecker().check((UserDetails) authentication.getPrincipal());
                //SecurityContextHolder에 Authentication 주체를 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }


        }

        //다음 필터 호출
        chain.doFilter(request,response);
    }
}

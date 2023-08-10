package com.smalldogg.springsecurityjwtexample.service;

import com.smalldogg.springsecurityjwtexample.model.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class UserDetailService {

    public UserDetails loadUserByUsername(Long id) {
        //id로부터 사용자 정보를 조회

        //사용자 존재여부 확인

        return new CustomUserDetails();
    }
}

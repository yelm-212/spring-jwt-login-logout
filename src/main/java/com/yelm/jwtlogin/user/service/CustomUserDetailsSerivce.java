package com.yelm.jwtlogin.user.service;

import com.yelm.jwtlogin.user.entity.CustomUserDetails;
import com.yelm.jwtlogin.user.entity.UserEntity;
import com.yelm.jwtlogin.user.mapper.UserMapper;
import com.yelm.jwtlogin.user.vo.UserResponseVO;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomUserDetailsSerivce implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserResponseVO userVO = userMapper.selectUserByUsername(username);

        if (userVO == null) {
            throw new UsernameNotFoundException(username);
        }

        return new CustomUserDetails(UserEntity.builder()
                                        .id(userVO.getId())
                                        .username(userVO.getUsername())
                                        .role(userVO.getRole())
                                        .password(userVO.getPassword())
                                        .build());
    }
}

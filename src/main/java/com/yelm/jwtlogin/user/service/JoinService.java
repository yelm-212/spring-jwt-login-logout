package com.yelm.jwtlogin.user.service;

import com.yelm.jwtlogin.user.entity.UserEntity;
import com.yelm.jwtlogin.user.mapper.UserMapper;
import com.yelm.jwtlogin.user.vo.JoinDTO;
import com.yelm.jwtlogin.user.vo.UserRequestVO;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class JoinService {

    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    public ResponseEntity joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        boolean isExist = userMapper.existsUserByUsername(username);

        if (isExist) {
            return ResponseEntity.badRequest()
                    .body("User already exists");
        }

        userMapper.insertUser(UserRequestVO.builder()
                        .username(username)
                        .password(passwordEncoder.encode(password))
                        .role("ROLE_USER")
                .build());

        return ResponseEntity.ok()
                            .body(joinDTO.getUsername());
    }
}
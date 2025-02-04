package com.yelm.jwtlogin.user.vo;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
@AllArgsConstructor
public class LoginRequestDTO {
    private String username;
    private String password;
}

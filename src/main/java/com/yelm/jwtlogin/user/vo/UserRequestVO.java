package com.yelm.jwtlogin.user.vo;

import lombok.Getter;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRequestVO {
    private String username;
    private String password;
    private String role;
}


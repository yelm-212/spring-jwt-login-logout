package com.yelm.jwtlogin.user.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponseVO {
    private int id;
    private String username;
    private String password;    // Authenticate
    private String role;
}

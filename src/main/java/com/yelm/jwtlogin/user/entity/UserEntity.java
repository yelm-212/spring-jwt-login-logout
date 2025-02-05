package com.yelm.jwtlogin.user.entity;

import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {

    private int id;

    private String username;
    private String password;

    private String role;
}
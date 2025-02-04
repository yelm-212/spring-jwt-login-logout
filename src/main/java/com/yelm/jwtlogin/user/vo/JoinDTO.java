package com.yelm.jwtlogin.user.vo;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JoinDTO {
    private String username;
    private String password;
}

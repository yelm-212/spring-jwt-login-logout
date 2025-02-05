package com.yelm.jwtlogin.jwt;

import com.yelm.jwtlogin.blacklist.TokenBlacklistService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;


@RequiredArgsConstructor
public class JwtLogoutHandler implements LogoutHandler {
    private final TokenBlacklistService blacklistService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            blacklistService.blacklistToken(token);
        }
    }
}


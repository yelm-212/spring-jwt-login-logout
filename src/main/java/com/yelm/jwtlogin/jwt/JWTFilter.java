package com.yelm.jwtlogin.jwt;

import com.yelm.jwtlogin.user.entity.CustomUserDetails;
import com.yelm.jwtlogin.user.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@AllArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Find Authorization Header
        String authorization= request.getHeader("Authorization");

        // Authorization Header
        if ( authorization == null || !authorization.startsWith("Bearer ")) {

            log.debug("Invalid Authorization header");
            filterChain.doFilter(request, response);

            return;
        }

        log.debug("authorization now");
        String token = authorization.split(" ")[1];

        if (jwtUtil.isExpired(token)) {

            log.debug("Token expired");
            filterChain.doFilter(request, response);

            return;
        }

        // Get username, role from token
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // userEntity
        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .role(role)
                .password(null)
                .build();

        // UserDetails
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // Auth
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
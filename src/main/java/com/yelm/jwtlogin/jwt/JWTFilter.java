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
import java.io.PrintWriter;

@Slf4j
@AllArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Skip this filter when reissue
        if (request.getRequestURI().equals("/reissue")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Find Authorization Header - Access Token -
        String authorization= request.getHeader("Authorization");

        // if AccessToken doesn't exist, go to next filter
        if (authorization == null){
            filterChain.doFilter(request, response);
            return;
        }

        // Check Authorization Header
        if (!authorization.startsWith("Bearer ")) {
            PrintWriter writer = response.getWriter();
            writer.print("Invalid Authorization header");
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Access token authorization started");
        String token = authorization.split(" ")[1];

        if (jwtUtil.isExpired(token)) {
            PrintWriter writer = response.getWriter();
            writer.print("Access Token expired");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // Check if this token is Access token
        if (!jwtUtil.getCategory(token).equals("access")) {
            PrintWriter writer = response.getWriter();
            writer.print("Invalid token category");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
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
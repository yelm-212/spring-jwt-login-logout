package com.yelm.jwtlogin.config;

import com.yelm.jwtlogin.user.entity.CustomUserDetails;
import com.yelm.jwtlogin.user.service.CustomUserDetailsSerivce;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@AllArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsSerivce userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        try {
            // 사용자 조회
            CustomUserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 비밀번호 검증
            if (!passwordEncoder.matches(password, userDetails.getPassword())) {
                throw new BadCredentialsException("Incorrect password");
            }

            // 계정 상태 검증
            if (!userDetails.isEnabled()) {
                throw new DisabledException("Inactive user");
            }
            if (!userDetails.isAccountNonLocked()) {
                throw new LockedException("Locked user");
            }
            if (!userDetails.isAccountNonExpired()) {
                throw new AccountExpiredException("Expired user");
            }
            if (!userDetails.isCredentialsNonExpired()) {
                throw new CredentialsExpiredException("User credentials expired");
            }

            return new UsernamePasswordAuthenticationToken(
                    userDetails,
                    password,
                    userDetails.getAuthorities()
            );

        } catch (UsernameNotFoundException e) {
            throw new UsernameNotFoundException("Username not found");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

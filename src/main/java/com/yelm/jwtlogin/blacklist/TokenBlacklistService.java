package com.yelm.jwtlogin.blacklist;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.yelm.jwtlogin.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    private final JWTUtil jwtUtil;
    private final Cache<String, String> tokenBlacklist = Caffeine.newBuilder()
            .expireAfterWrite(60, TimeUnit.MINUTES) // 기본 TTL (fallback)
            .removalListener((String key, String value, RemovalCause cause) ->
                    log.debug("Token Expired: {} Cause: {}", key, cause))
            .build();


    public void blacklistToken(String token) {
        long ttl = jwtUtil.getExpirationTime(token) - System.currentTimeMillis();

        if (ttl > 0) {
            tokenBlacklist.policy().expireVariably().ifPresent(policy -> {
                policy.put(token, "blacklisted", Duration.ofMillis(ttl));
            });

            log.debug("Token Blacklisted: {}, TTL: {}ms", token, ttl);
        } else {
            log.debug("Token Expired: {}ms", ttl);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklist.getIfPresent(token) != null;
    }
}
package com.yelm.jwtlogin.blacklist;

import com.yelm.jwtlogin.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    private final StringRedisTemplate redisTemplate;
    private final JWTUtil jwtUtil;

    public void blacklistToken(String token) {
        // 토큰의 남은 만료 시간 계산
        long ttl = jwtUtil.getExpirationTime(token) - System.currentTimeMillis();

        if (ttl > 0) {
            // Redis에 블랙리스트 추가 (Key: token, Value: "blacklisted")
            redisTemplate.opsForValue()
                    .set("blacklist:" + token, "blacklisted", ttl, TimeUnit.MILLISECONDS);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(
                redisTemplate.hasKey("blacklist:" + token)
        );
    }
}
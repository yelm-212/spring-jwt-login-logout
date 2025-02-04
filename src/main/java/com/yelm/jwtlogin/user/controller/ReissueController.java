package com.yelm.jwtlogin.user.controller;

import com.yelm.jwtlogin.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@ResponseBody
@AllArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // Get refresh token from cookie
        String refresh = null;
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return new ResponseEntity<>("no cookies present", HttpStatus.BAD_REQUEST);
        }

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
                break;
            }
        }

        try {
            if (!jwtUtil.getCategory(refresh).equals("refresh")) {
                return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
            }

            if (jwtUtil.isExpired(refresh)) {
                return new ResponseEntity<>("refresh token expired", HttpStatus.UNAUTHORIZED);
            }

            String username = jwtUtil.getUsername(refresh);
            String role = jwtUtil.getRole(refresh);

            String newAccess = jwtUtil.createJwt("access", username, role);
            String newRefresh = jwtUtil.createJwt("refresh", username, role);

            response.addCookie(createCookie("refresh", newRefresh));

            return ResponseEntity.ok()
                    .header("Authorization", "Bearer " + newAccess)
                    .body("Token reissued successfully");

        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refresh token expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>("token validation failed: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        cookie.setHttpOnly(true);

        return cookie;
    }
}
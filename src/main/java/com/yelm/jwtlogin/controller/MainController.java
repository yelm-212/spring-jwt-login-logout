package com.yelm.jwtlogin.controller;

import com.yelm.jwtlogin.user.entity.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@Slf4j
public class MainController {

    @GetMapping("/")
    public ResponseEntity mainP() {

        return ResponseEntity.ok("Main Controller");
    }

    @GetMapping("/hello")
    public ResponseEntity helloP(@AuthenticationPrincipal CustomUserDetails userDetails) {

//        SecurityContextHolder.getContext().getAuthentication().getName();
        log.debug("Username : {}", userDetails.getUsername());
//        SecurityContextHolder.getContext().getAuthentication().getAuthorities()
//                .iterator().next().getAuthority();
        log.debug("Role : {}", userDetails.getRole());

        return ResponseEntity.ok("Hello " + userDetails.getUsername());
    }
}

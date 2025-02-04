package com.yelm.jwtlogin.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Iterator;

@Controller
@ResponseBody
@Slf4j
public class MainController {

    @GetMapping("/")
    public ResponseEntity mainP() {

        return ResponseEntity.ok("Main Controller");
    }

    @GetMapping("/hello")
    public ResponseEntity helloP() {

        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        SecurityContextHolder.getContext().getAuthentication().getAuthorities()
                .iterator().next().getAuthority();
        log.debug("Username : {}", username);
        log.debug("Role : {}", SecurityContextHolder.getContext().getAuthentication().getAuthorities()
                .iterator().next().getAuthority());

        return ResponseEntity.ok("Hello " + username);
    }
}

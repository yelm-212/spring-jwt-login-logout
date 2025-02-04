package com.yelm.jwtlogin.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/admin")
@ResponseBody
public class AdminController {

    @GetMapping
    public ResponseEntity adminP() {

        return ResponseEntity.ok().body("Hello Admin");
    }
}

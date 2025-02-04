package com.yelm.jwtlogin.user.controller;

import com.yelm.jwtlogin.user.service.JoinService;
import com.yelm.jwtlogin.user.vo.JoinDTO;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Slf4j
@Controller
@AllArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public ResponseEntity joinProcess(@RequestBody JoinDTO joinDTO) {

        log.debug(joinDTO.getUsername());

        return joinService.joinProcess(joinDTO);
    }
}

package com.security.demo.controller;

import com.security.demo.dto.JoinDto;
import com.security.demo.jwt.JwtTokenUtil;
import com.security.demo.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Api {

    private final MemberService memberService;
    private final JwtTokenUtil jwtTokenUtil;

    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    @PostMapping("/join")
    public String join(@RequestBody JoinDto joinDto) {
        memberService.join(joinDto);
        return "회원가입 완료";
    }

    @PostMapping("/join/admin")
    public String joinAdmin(@RequestBody JoinDto joinDto) {
        memberService.joinAdmin(joinDto);
        return "어드민 회원 가입 완료";
    }
}

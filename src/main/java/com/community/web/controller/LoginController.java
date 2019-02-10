package com.community.web.controller;

import com.community.web.annotation.SocialUser;
import com.community.web.domain.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/loginSuccess")
    public String loginSuccess(@SocialUser User user) {
        return "redirect:/board/list";
    }
}

package com.xhuicloud.auth.server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ServerController {

    @GetMapping("/login")
    String login() {
        return "login";
    }

    /**
     * 登录成功后
     *
     * @return
     */
    @ResponseBody
    @GetMapping("/")
    public Authentication authentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication;
    }

    @ResponseBody
    @GetMapping("/private")
    public String privateResource() {
        return "private";
    }
}

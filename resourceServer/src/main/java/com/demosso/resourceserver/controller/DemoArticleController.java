package com.demosso.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoArticleController {
    @GetMapping("/demo/public")
    public String demoPublic() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "demo public string";
    }

    @PreAuthorize("hasAuthority('ARTICLE_READ')")
    @GetMapping("/demo/read")
    public String read() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "demo read string";
    }

    @PreAuthorize("hasAuthority('ARTICLE_WRITE')")
    @GetMapping("/demo/write")
    public String write() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "demo write string";
    }
}

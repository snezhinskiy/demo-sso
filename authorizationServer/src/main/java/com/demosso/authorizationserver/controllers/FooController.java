package com.demosso.authorizationserver.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FooController {

    @GetMapping(path = "/foo")
    public String foo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "foo";
    }
}

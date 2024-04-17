package com.marcuslull.springauthserver.controllers;

import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

    @GetMapping({"/", ""})
    public String index(@CurrentSecurityContext SecurityContext context, Model model) {
        // demonstrating AnonymousAuthentication
        model.addAttribute("context", context);
        return "index";
    }

    @GetMapping("/another-page")
    public String anotherPage() {
        return "another-page";
    }
}

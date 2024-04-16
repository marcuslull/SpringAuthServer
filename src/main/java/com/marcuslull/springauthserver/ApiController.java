package com.marcuslull.springauthserver;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Controller
@EnableMethodSecurity
public class ApiController {
    private final DemoService demoService;

    public ApiController(DemoService demoService) {
        this.demoService = demoService;
    }

    @GetMapping("/api/should-work-for-super")
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER')") // only SUPER and higher can use the API
    public ResponseEntity<DemoAccountEntity> getSuperAccount() {
        return ResponseEntity.ok(demoService.returnAccount());
    }

    @GetMapping("/api/should-work-for-admin")
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER')") // only SUPER and higher can use the API
    public ResponseEntity<DemoAccountEntity> getAdminAccount() {
        return ResponseEntity.ok(demoService.returnAccount2());
    }

    @GetMapping("/api/filter-by-user")
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER')") // only SUPER and higher can use the API
    public ResponseEntity<Collection<DemoAccountEntity>> filterByUser() {
        DemoAccountEntity demoAccountEntity1 = new DemoAccountEntity();
        demoAccountEntity1.setOwner("super");
        DemoAccountEntity demoAccountEntity2 = new DemoAccountEntity();
        demoAccountEntity2.setOwner("admin");
        List<DemoAccountEntity> demoAccountEntityList = new ArrayList<>();
        demoAccountEntityList.add(demoAccountEntity1);
        demoAccountEntityList.add(demoAccountEntity2);

        Collection<DemoAccountEntity> demoAccountEntityCollection = demoService.parameterFilteringExample(demoAccountEntityList);

        return ResponseEntity.ok(demoAccountEntityCollection);
    }
}

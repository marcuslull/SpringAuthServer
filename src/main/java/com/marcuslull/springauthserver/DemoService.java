package com.marcuslull.springauthserver;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collection;

@Service
// A more fine-grained authorization technique than request level authorization
@EnableMethodSecurity // Required for springboot projects - this enables the Pre- and Post-annotations
// can also be used at the class level, method level overrides class level
public class DemoService {

    // METHOD LEVEL AUTHORIZATION
    // multiple annotations are allowed but only one of each type. The logic uses SpEL
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    // Spring AOP PointCut checks for the authority before processing the method
    @PostAuthorize("returnObject.owner == authentication.name")
    // Spring AOP Pointcut that checks for ownership after the method processes
    public DemoAccountEntity methodLevelSecurityExample() {
        // do stuff - the object returned must have an owner property to compare against in the PostAuthorize annotation
        DemoAccountEntity demoAccountEntity = new DemoAccountEntity();
        demoAccountEntity.setOwner("admin");
        return demoAccountEntity;
    }

    // a good way to handle secure data object references is to create a custom annotation:
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PostAuthorize("returnObject.owner == authentication.name")
    public @interface RequireOwnership {
    }

    //then apply it to all methods that need to return a data object
    @RequireOwnership // if the principal owns the object it will return, otherwise a 403
    public DemoAccountEntity returnAccount() {
        DemoAccountEntity demoAccountEntity1 = new DemoAccountEntity();
        demoAccountEntity1.setOwner("super");
        return demoAccountEntity1;
    }

    // another custom annotation example
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('ADMIN')")
    public @interface IsAdmin {
    }

    // annotation applied
    @IsAdmin // only returned if the user is an ADMIN
    public DemoAccountEntity returnAccount2() {
        return new DemoAccountEntity();
    }


    // METHOD LEVEL PARAMETER FILTERING
//    @PreFilter("filterObject.owner == authentication.name")
    // the method will only have access to the objects that pass the filter
    @PostFilter("filterObject.owner == authentication.name")
    // the method will only return instances that pass the filter
    public Collection<DemoAccountEntity> parameterFilteringExample(Collection<DemoAccountEntity> accounts) {
        // the DemoAccountEntity instances passed in must be owned by the principal
        // @Pre/PostFilter supports arrays, collections, maps, and streams (so long as the stream is still open)
        return accounts;
    }
}

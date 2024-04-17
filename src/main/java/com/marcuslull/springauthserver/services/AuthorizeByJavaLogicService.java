package com.marcuslull.springauthserver.services;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;

// METHOD LEVEL SECURITY JAVA BASED
// define a bean with the logic passing in MethodSecurityExpressionOperations
@Component("javaLogic") // name for the reference
public class AuthorizeByJavaLogicService {

    public boolean decide(MethodSecurityExpressionOperations operations) {
        // authorization login here
        return true;
    }

    // then reference it in the method to authorize
    @PreAuthorize("@javaLogic.decide(#root)")
    public String someControllerEndpoint() {
        // ...
        return null;
    }
}

package com.autmaple.aladmin.components;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;

@RequiredArgsConstructor
public class TokenProvider implements InitializingBean {
    private final SecurityProperties properties;

    @Override
    public void afterPropertiesSet() throws Exception {

    }
}

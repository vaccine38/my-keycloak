package com.keycloak.springmvc.config;

import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@ConfigurationProperties(prefix = "policy-enforcer")
@PropertySource(value = {"classpath:policy-enforcer.yaml"}, factory = YamlPropertySourceFactory.class)
public class PolicyEnforcerConfigCustom extends PolicyEnforcerConfig {
}

package com.example.certmgr.config;


import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

@AutoConfiguration
@EnableJpaRepositories(basePackages = "com.example.certmgr.repository")
@EntityScan(basePackages = "com.example.certmgr.entity")
@EnableScheduling
public class AplicationConfig {
}

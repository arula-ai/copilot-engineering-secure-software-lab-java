package com.securelabs;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Secure Development Lab - Spring Boot Application
 *
 * WARNING: This application contains intentionally vulnerable code for educational purposes.
 * DO NOT deploy to production or use vulnerable patterns in real applications.
 */
@SpringBootApplication
public class SecureLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureLabApplication.class, args);
    }
}

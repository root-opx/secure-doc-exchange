package com.secure.exchange;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.io.File;
import java.net.URL;

@SpringBootApplication
@org.springframework.scheduling.annotation.EnableAsync
public class SecureExchangeApplication {

    public static void main(String[] args) {
        // Tell Java where the Truststore is BEFORE Spring starts
        // We look for it in the classpath to get a valid absolute path
        try {
            URL truststoreUrl = SecureExchangeApplication.class.getClassLoader().getResource("truststore.p12");
            if (truststoreUrl != null) {
                String path = new File(truststoreUrl.toURI()).getAbsolutePath();
                System.setProperty("javax.net.ssl.trustStore", path);
                System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
                System.out.println("DEBUG: Truststore localized at: " + path);
            }
        } catch (Exception e) {
            System.err.println("WARNING: Could not resolve truststore.p12 path: " + e.getMessage());
        }

        SpringApplication.run(SecureExchangeApplication.class, args);
    }
}

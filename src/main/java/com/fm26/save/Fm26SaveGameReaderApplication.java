package com.fm26.save;

import com.fm26.save.config.SaveImportProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(SaveImportProperties.class)
public class Fm26SaveGameReaderApplication {
    public static void main(String[] args) {
        SpringApplication.run(Fm26SaveGameReaderApplication.class, args);
    }
}

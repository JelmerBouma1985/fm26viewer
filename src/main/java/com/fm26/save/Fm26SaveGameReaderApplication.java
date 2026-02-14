package com.fm26.save;

import com.fm26.save.savegame.FmSaveProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableConfigurationProperties(FmSaveProperties.class)
public class Fm26SaveGameReaderApplication {
    public static void main(String[] args) {
        SpringApplication.run(Fm26SaveGameReaderApplication.class, args);
    }
}

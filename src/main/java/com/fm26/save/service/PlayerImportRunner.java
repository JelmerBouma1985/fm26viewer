package com.fm26.save.service;

import com.fm26.save.config.SaveImportProperties;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class PlayerImportRunner implements CommandLineRunner {

    private final SaveImportServiceDelegate delegate;

    public PlayerImportRunner(SaveImportServiceDelegate delegate) {
        this.delegate = delegate;
    }

    @Override
    public void run(String... args) throws Exception {
        delegate.runImportIfEnabled();
    }

    @Component
    static class SaveImportServiceDelegate {
        private final PlayerImportService importService;
        private final SaveImportProperties properties;

        SaveImportServiceDelegate(PlayerImportService importService, SaveImportProperties properties) {
            this.importService = importService;
            this.properties = properties;
        }

        void runImportIfEnabled() throws Exception {
            if (!properties.isEnabled()) {
                return;
            }
            importService.importConfiguredSave();
        }
    }
}

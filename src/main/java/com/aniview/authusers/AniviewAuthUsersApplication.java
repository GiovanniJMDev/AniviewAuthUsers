package com.aniview.authusers;

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AniviewAuthUsersApplication {

    private static final Logger log = LoggerFactory.getLogger(AniviewAuthUsersApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(AniviewAuthUsersApplication.class, args);
    }

    @Bean
    public CommandLineRunner testDatabaseConnection(DataSource dataSource) {
        return args -> {
            try (Connection connection = dataSource.getConnection()) {
                if (connection.isValid(1)) {
                    log.info("Conexión a la base de datos exitosa!");
                } else {
                    log.info("Fallo en la conexión a la base de datos.");
                }
            } catch (SQLException e) {
                log.info("Error al conectar a la base de datos: " + e.getMessage());
            }
        };
    }

}

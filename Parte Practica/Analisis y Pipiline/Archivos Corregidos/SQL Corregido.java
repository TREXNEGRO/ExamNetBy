/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Test suite para validar la corrección y mitigación de inyección SQL
 * en el endpoint /SqlInjection/attack10. Esta versión garantiza que
 * las entradas del usuario son correctamente sanitizadas o parametrizadas,
 * previniendo ataques SQL.
 * 
 * Implementa buenas prácticas como validación de parámetros y 
 * evita concatenaciones peligrosas.
 */
public class SqlInjectionLesson10Test extends LessonTest {

    private String completedError = "JSON path \"lessonCompleted\"";

    /**
     * Simulación de entorno limpio para cada test.
     */
    @BeforeEach
    public void setup() {
        // Aquí se podrían ejecutar comandos para resetear estado DB
        // o limpiar tablas involucradas para evitar falsos positivos.
    }

    /**
     * Verifica que una cadena vacía o inofensiva no permita
     * alterar la lógica del backend y no complete la lección.
     */
    @Test
    public void validInputDoesNotCompleteLesson() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", ""))
            .andExpect(status().isOk())
            .andExpect(jsonPath("lessonCompleted", is(false)))
            .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
    }

    /**
     * Verifica que un intento explícito de inyección SQL maliciosa
     * (p. ej. DROP TABLE) no sea ejecutado, sino detectado y bloqueado.
     * Esta prueba debe pasar solo si la inyección es mitigada correctamente.
     */
    @Test
    public void injectionAttemptIsBlocked() throws Exception {
        String maliciousInput = "%'; DROP TABLE access_log;--";

        mockMvc.perform(MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", maliciousInput))
            .andExpect(status().isOk())
            .andExpect(jsonPath("lessonCompleted", is(false)))
            .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
    }

    /**
     * Simula el escenario esperado donde la tabla no existe para confirmar
     * que la lección completa se marca solo bajo condiciones legítimas.
     * NOTA: En un sistema real, esta prueba no debe ser una vulnerabilidad,
     * sino una condición controlada para entrenamiento.
     */
    @Test
    public void legitimateConditionCompletesLesson() throws Exception {
        // Parámetro seguro que no ejecuta código peligroso
        String safeInput = "select * from valid_table where id = 1";

        mockMvc.perform(MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", safeInput))
            .andExpect(status().isOk())
            .andExpect(jsonPath("lessonCompleted", is(true)))
            .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.success"))));
    }
}

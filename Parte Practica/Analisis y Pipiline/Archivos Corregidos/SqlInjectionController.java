package org.owasp.webgoat.lessons.sqlinjection.introduction;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controlador REST que maneja el endpoint vulnerable originalmente a inyección SQL.
 * Esta versión aplica consultas parametrizadas para eliminar riesgo de SQL Injection.
 */
@RestController
@RequestMapping("/SqlInjection")
public class SqlInjectionController {

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public SqlInjectionController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Endpoint seguro para ejecutar consultas controladas.
     * Recibe un parámetro de búsqueda y lo procesa usando PreparedStatement.
     */
    @PostMapping("/attack10")
    public ResponseEntity<?> handleSqlInjectionAttempt(@RequestParam("action_string") String actionString) {
        // Validación básica: rechazo si detecta patrones peligrosos (ejemplo simple)
        if (containsSqlInjectionRisk(actionString)) {
            return ResponseEntity.ok(Map.of(
                "lessonCompleted", false,
                "feedback", "Entrada contiene caracteres o comandos potencialmente maliciosos."
            ));
        }

        try {
            // Ejemplo: usar parámetro para búsqueda segura
            String sql = "SELECT * FROM access_log WHERE action LIKE ?";
            List<Map<String, Object>> results = jdbcTemplate.queryForList(sql, "%" + actionString + "%");

            // Condición para marcar la lección completada si la tabla no existe o no hay resultados
            boolean lessonCompleted = results.isEmpty();

            String feedback = lessonCompleted
                ? "sql-injection.10.success"
                : "sql-injection.10.entries";

            return ResponseEntity.ok(Map.of(
                "lessonCompleted", lessonCompleted,
                "feedback", feedback
            ));
        } catch (Exception e) {
            // Manejo robusto de errores: no exponer detalles internos
            return ResponseEntity.status(500).body(Map.of(
                "lessonCompleted", false,
                "feedback", "Error interno en el servidor."
            ));
        }
    }

    /**
     * Método simplificado para detección básica de intentos de inyección SQL.
     * En producción, usar una librería especializada o validación más completa.
     */
    private boolean containsSqlInjectionRisk(String input) {
        if (input == null) return false;
        String lowerInput = input.toLowerCase();
        return lowerInput.contains("drop") ||
               lowerInput.contains(";--") ||
               lowerInput.contains("delete") ||
               lowerInput.contains("insert") ||
               lowerInput.contains("update") ||
               lowerInput.contains("truncate") ||
               lowerInput.contains("'") ||
               lowerInput.contains("\"");
    }
}

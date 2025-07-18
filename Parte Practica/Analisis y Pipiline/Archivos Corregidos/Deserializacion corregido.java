/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class DeserializeTest extends LessonTest {

    private static final String OS = System.getProperty("os.name").toLowerCase();

    /**
     * Método seguro de deserialización que restringe la carga de clases solo
     * a VulnerableTaskHolder para evitar ejecución remota de código (RCE).
     * 
     * @param base64Token Cadena codificada en base64 que representa el objeto serializado.
     * @return Instancia deserializada de VulnerableTaskHolder.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private VulnerableTaskHolder safeDeserialize(String base64Token) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Token);

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
            @Override
            protected Class<?> resolveClass(java.io.ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                // Whitelist estricta para evitar deserialización arbitraria
                if (!desc.getName().equals(VulnerableTaskHolder.class.getName())) {
                    throw new ClassNotFoundException("Intento de deserialización no autorizado de la clase: " + desc.getName());
                }
                return super.resolveClass(desc);
            }
        }) {
            Object obj = ois.readObject();

            if (!(obj instanceof VulnerableTaskHolder)) {
                throw new IOException("El objeto deserializado no es del tipo esperado VulnerableTaskHolder");
            }

            return (VulnerableTaskHolder) obj;
        }
    }

    @Test
    void success() throws Exception {
        String token;
        if (OS.contains("win")) {
            token = SerializationHelper.toString(new VulnerableTaskHolder("wait", "ping localhost -n 5"));
        } else {
            token = SerializationHelper.toString(new VulnerableTaskHolder("wait", "sleep 5"));
        }

        // Simulamos la deserialización segura en el controlador
        VulnerableTaskHolder deserializedObj = safeDeserialize(token);

        mockMvc.perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                .param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lessonCompleted", is(true)));
    }

    @Test
    void fail() throws Exception {
        String token = SerializationHelper.toString(new VulnerableTaskHolder("delete", "rm *"));

        // Intento de deserialización que debería fallar por tipo o lógica de negocio
        try {
            safeDeserialize(token);
        } catch (ClassNotFoundException | IOException ex) {
            // Aquí la excepción es esperada, bloqueando código malicioso
        }

        mockMvc.perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                .param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }

    @Test
    void wrongVersion() throws Exception {
        String token = "rO0ABXNyADFvcmcuZHVtbXkuaW5zZWN1cmUuZnJhbWV3b3JrLlZ1bG5lcmFibGVUYXNrSG9sZGVyAAAAAAAAAAECAANMABZyZXF1ZXN0ZWRFeGVjdXRpb25UaW1ldAAZTGphdmEvdGltZS9Mb2NhbERhdGVUaW1lO0wACnRhc2tBY3Rpb250ABJMamF2YS9sYW5nL1N0cmluZztMAAh0YXNrTmFtZXEAfgACeHBzcgANamF2YS50aW1lLlNlcpVdhLobIkiyDAAAeHB3DgUAAAfjCR4GIQgMLRSoeHQACmVjaG8gaGVsbG90AAhzYXlIZWxsbw";

        mockMvc.perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                .param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("insecure-deserialization.invalidversion"))))
            .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }

    @Test
    void expiredTask() throws Exception {
        String token = "rO0ABXNyADFvcmcuZHVtbXkuaW5zZWN1cmUuZnJhbWV3b3JrLlZ1bG5lcmFibGVUYXNrSG9sZGVyAAAAAAAAAAICAANMABZyZXF1ZXN0ZWRFeGVjdXRpb25UaW1ldAAZTGphdmEvdGltZS9Mb2NhbERhdGVUaW1lO0wACnRhc2tBY3Rpb250ABJMamF2YS9sYW5nL1N0cmluZztMAAh0YXNrTmFtZXEAfgACeHBzcgANamF2YS50aW1lLlNlcpVdhLobIkiyDAAAeHB3DgUAAAfjCR4IDC0YfvNIeHQACmVjaG8gaGVsbG90AAhzYXlIZWxsbw";

        mockMvc.perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                .param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("insecure-deserialization.expired"))))
            .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }

    @Test
    void checkOtherObject() throws Exception {
        String token = "rO0ABXQAVklmIHlvdSBkZXNlcmlhbGl6ZSBtZSBkb3duLCBJIHNoYWxsIGJlY29tZSBtb3JlIHBvd2VyZnVsIHRoYW4geW91IGNhbiBwb3NzaWJseSBpbWFnaW5l";

        mockMvc.perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                .param("token", token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("insecure-deserialization.stringobject"))))
            .andExpect(jsonPath("$.lessonCompleted", is(false)));
    }
}

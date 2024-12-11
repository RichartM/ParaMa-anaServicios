package com.example.PaseListaApi.auth.utils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Clase abstracta utilizada para personalizar la deserialización de objetos
 * del tipo SimpleGrantedAuthority con la biblioteca Jackson.
 */
public abstract class SimpleGrantedAuthorityJsonCreator {

    /**
     * Constructor que permite deserializar un objeto SimpleGrantedAuthority desde un JSON.
     *
     * @param role El valor de la propiedad "authority" del JSON, que representa el rol o autoridad del usuario.
     */
    @JsonCreator
    public SimpleGrantedAuthorityJsonCreator(@JsonProperty("authority") String role) {
        // Este constructor no implementa lógica específica, ya que actúa como un enlace
        // para Jackson durante la deserialización.
    }
}

package com.example.PaseListaApi.auth;

/**
 * Clase personalizada para manejar excepciones específicas relacionadas con el proceso de autenticación.
 * Hereda de RuntimeException, lo que significa que es una excepción no verificada (unchecked exception).
 */
public class AuthenticationProcessingException extends RuntimeException {

    /**
     * Constructor que permite crear una nueva instancia de AuthenticationProcessingException.
     *
     * @param message El mensaje de error que describe la causa de la excepción.
     * @param cause El objeto Throwable que representa la causa original de la excepción.
     */
    public AuthenticationProcessingException(String message, Throwable cause) {
        // Llama al constructor de la clase padre (RuntimeException) con el mensaje y la causa proporcionada.
        super(message, cause);
    }
}

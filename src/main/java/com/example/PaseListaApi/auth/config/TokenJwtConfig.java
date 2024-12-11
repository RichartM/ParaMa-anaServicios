package com.example.PaseListaApi.auth.config;

// Importación de la clase Keys para la creación de claves secretas con el estándar HMAC
import io.jsonwebtoken.security.Keys;

// Importación de la librería Lombok para la generación automática de getters
import lombok.Getter;

// Importaciones de Spring para la configuración y acceso a valores de propiedades
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

// Importación de la clase SecretKey para representar una clave secreta
import javax.crypto.SecretKey;

/**
 * Clase de configuración para manejar los tokens JWT en la aplicación.
 */
@Getter // Genera automáticamente los getters para los atributos de la clase mediante Lombok
@Configuration // Define esta clase como una clase de configuración en Spring
public class TokenJwtConfig {

    // Clave secreta utilizada para firmar y validar los tokens JWT
    public final SecretKey secretKey;

    // Prefijo estándar para los tokens JWT en el encabezado de autorización
    public static final String PREFIX_TOKEN = "Bearer ";

    // Nombre del encabezado HTTP donde se espera encontrar el token JWT
    public static final String HEADER_AUTHORIZATION = "Authorization";

    // Tipo de contenido esperado en las respuestas que utiliza esta configuración
    public static final String CONTENT_TYPE = "application/json";

    /**
     * Constructor que inicializa la clave secreta para JWT.
     * @param secret La clave secreta obtenida desde las propiedades de configuración (application.properties o .yaml).
     */
    public TokenJwtConfig(@Value("${jwt.secret}") String secret) {
        // Convierte la clave secreta de cadena a una clave secreta HMAC con una longitud adecuada
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }
}

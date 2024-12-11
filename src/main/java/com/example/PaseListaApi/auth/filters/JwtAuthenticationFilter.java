package com.example.PaseListaApi.auth.filters;

// Importaciones relacionadas con autenticación y JWT
import com.example.PaseListaApi.auth.AuthenticationProcessingException;
import com.example.PaseListaApi.auth.config.TokenJwtConfig;
import com.example.PaseListaApi.auth.model.AuthDetails;
import com.example.PaseListaApi.model.user_info.Users_info;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

// Importaciones de Servlet y Spring Security
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

// Importación de constantes relacionadas con JWT
import static com.example.PaseListaApi.auth.config.TokenJwtConfig.*;

/**
 * Filtro de autenticación basado en JWT que extiende UsernamePasswordAuthenticationFilter.
 * Maneja el proceso de autenticación de usuarios y la generación de tokens JWT.
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final TokenJwtConfig tokenJwtConfig;

    /**
     * Constructor que inicializa el filtro con el AuthenticationManager y configuración de JWT.
     * @param authenticationManager El administrador de autenticación.
     * @param tokenJwtConfig Configuración del token JWT.
     */
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, TokenJwtConfig tokenJwtConfig, String loginurl) {
        this.authenticationManager = authenticationManager;
        this.tokenJwtConfig = tokenJwtConfig;
        setFilterProcessesUrl(loginurl);
    }

    /**
     * Método que intenta autenticar al usuario con las credenciales proporcionadas en la solicitud.
     * @param request Solicitud HTTP que contiene los datos de autenticación.
     * @param response Respuesta HTTP.
     * @return Un objeto de tipo Authentication si la autenticación es exitosa.
     * @throws AuthenticationException Si la autenticación falla.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        Users_info user;
        String username;
        String password;
        try {
            // Deserializa el cuerpo de la solicitud a un objeto de tipo Users_info
            user = new ObjectMapper().readValue(request.getInputStream(), Users_info.class);
            username = user.getEmail();
            password = user.getPassword();
        } catch (IOException e) {
            // Lanza una excepción personalizada si ocurre un error en el procesamiento
            throw new AuthenticationProcessingException("Error al procesar la autenticación", e);
        }

        // Crea un token de autenticación con las credenciales proporcionadas
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        // Autentica al usuario con el AuthenticationManager
        return authenticationManager.authenticate(authToken);
    }

    /**
     * Método que se ejecuta cuando la autenticación es exitosa.
     * Genera un token JWT y lo incluye en la respuesta HTTP.
     * @param request Solicitud HTTP.
     * @param response Respuesta HTTP.
     * @param chain Cadena de filtros.
     * @param authResult Resultado de la autenticación.
     * @throws IOException Si ocurre un error al escribir en la respuesta.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        // Obtiene los detalles del usuario autenticado
        AuthDetails user = (AuthDetails) authResult.getPrincipal();
        String username = user.getEmail();
        Collection<? extends GrantedAuthority> roles = user.getAuthorities();

        // Configura los claims (información adicional) del token
        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        // Genera el token JWT con los datos del usuario
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(tokenJwtConfig.getSecretKey())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // Token válido por 1 hora
                .compact();

        // Añade el token al encabezado de la respuesta
        response.addHeader(HEADER_AUTHORIZATION, PREFIX_TOKEN + token);

        // Extrae el rol principal del usuario
        String rol = roles.stream()
                .findFirst() // Obtiene el primer rol
                .map(GrantedAuthority::getAuthority)
                .orElse("Docente"); // Valor por defecto si no hay roles

        // Crea el cuerpo de la respuesta con información adicional
        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("email", username);
        body.put("rol", rol); // Incluye el rol en la respuesta

        // Escribe la respuesta en formato JSON
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(CONTENT_TYPE);
    }

    /**
     * Método que se ejecuta cuando la autenticación falla.
     * Devuelve un mensaje de error en el cuerpo de la respuesta.
     * @param request Solicitud HTTP.
     * @param response Respuesta HTTP.
     * @param failed Excepción lanzada por la autenticación fallida.
     * @throws IOException Si ocurre un error al escribir en la respuesta.
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        // Crea el cuerpo de la respuesta con el mensaje de error
        Map<String, Object> body = new HashMap<>();
        body.put("messsage", "Error en la autenticación: username o password es incorrecto");
        body.put("error", failed.getMessage());

        // Escribe la respuesta en formato JSON
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(CONTENT_TYPE);
    }
}

package com.example.PaseListaApi.auth.filters;

import com.example.PaseListaApi.auth.config.TokenJwtConfig;
import com.example.PaseListaApi.auth.utils.SimpleGrantedAuthorityJsonCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.PaseListaApi.auth.config.TokenJwtConfig.*;

/**
 * Este filtro se encarga de validar los tokens JWT para cada solicitud entrante.
 * Extiende la clase BasicAuthenticationFilter de Spring Security.
 */
public class JwtValidationFilter extends BasicAuthenticationFilter {
    private final TokenJwtConfig tokenJwtConfig; // Configuración del token JWT

    /**
     * Constructor que inicializa el filtro con el AuthenticationManager y la configuración del token.
     * @param authenticationManager El manejador de autenticación.
     * @param tokenJwtConfig La configuración del token JWT.
     */
    public JwtValidationFilter(AuthenticationManager authenticationManager, TokenJwtConfig tokenJwtConfig) {
        super(authenticationManager);
        this.tokenJwtConfig = tokenJwtConfig;
    }

    /**
     * Método principal que intercepta las solicitudes para validar el token JWT.
     * @param request La solicitud HTTP entrante.
     * @param response La respuesta HTTP saliente.
     * @param chain La cadena de filtros para continuar el procesamiento.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Obtiene el encabezado de autorización de la solicitud.
        String header = request.getHeader(HEADER_AUTHORIZATION);

        // Si no hay encabezado o no comienza con el prefijo esperado, continúa con la cadena de filtros.
        if (header == null || !header.startsWith(PREFIX_TOKEN)) {
            chain.doFilter(request, response);
            return;
        }

        // Elimina el prefijo del token para obtener el token puro.
        String token = header.replace(PREFIX_TOKEN, "");

        try {
            // Valida y decodifica el token usando la clave secreta configurada.
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(tokenJwtConfig.getSecretKey()) // Clave secreta para firmar/verificar el token.
                    .build()
                    .parseClaimsJws(token) // Decodifica el token.
                    .getBody();

            // Obtiene los roles del usuario del token.
            Object authoritiesClaims = claims.get("authorities");
            String username = claims.getSubject(); // Obtiene el nombre de usuario del token.

            // Convierte los roles del token en una colección de autoridades de Spring Security.
            Collection<? extends GrantedAuthority> authorities = List.of(new ObjectMapper()
                    .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityJsonCreator.class)
                    .readValue(authoritiesClaims.toString().getBytes(), SimpleGrantedAuthority[].class));

            // Crea un objeto de autenticación con el usuario y sus roles.
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

            // Establece la autenticación en el contexto de seguridad de Spring.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Continúa con la cadena de filtros.
            chain.doFilter(request, response);

        } catch (JwtException e) {
            // Si ocurre algún error al validar el token, envía una respuesta de error.
            Map<String, String> body = new HashMap<>();
            body.put("error", e.getMessage()); // Detalle del error.
            body.put("message", "El token no es válido"); // Mensaje amigable.

            // Escribe la respuesta de error como JSON.
            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setStatus(HttpStatus.UNAUTHORIZED.value()); // Código de estado 401 (no autorizado).
            response.setContentType(CONTENT_TYPE); // Tipo de contenido de la respuesta.
        }
    }
}

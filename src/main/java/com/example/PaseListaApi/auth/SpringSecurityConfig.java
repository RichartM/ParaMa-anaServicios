package com.example.PaseListaApi.auth;

import com.example.PaseListaApi.auth.config.TokenJwtConfig;
import com.example.PaseListaApi.auth.filters.JwtAuthenticationFilter;
import com.example.PaseListaApi.auth.filters.JwtValidationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * Configuración de seguridad para la aplicación, que establece las reglas de autenticación y autorización,
 * configuraciones de CORS, y los filtros de autenticación JWT.
 */
@Configuration
public class SpringSecurityConfig {

    // Inyección de dependencias necesarias para la configuración de seguridad
    private final AuthenticationConfiguration authenticationConfiguration;
    private final TokenJwtConfig tokenJwtConfig;

    // Constructor para inicializar la configuración de seguridad
    public SpringSecurityConfig(AuthenticationConfiguration authenticationConfiguration, TokenJwtConfig tokenJwtConfig) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.tokenJwtConfig = tokenJwtConfig;
    }

    /**
     * Bean que configura el codificador de contraseñas utilizando el algoritmo BCrypt.
     *
     * @return Un objeto de tipo PasswordEncoder que usará BCrypt para codificar contraseñas.
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); // Utiliza BCrypt para mayor seguridad
    }

    /**
     * Bean que configura el AuthenticationManager utilizado para gestionar la autenticación de los usuarios.
     *
     * @return Un objeto de tipo AuthenticationManager.
     * @throws Exception Si ocurre algún error al obtener el AuthenticationManager.
     */
    @Bean
    AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager(); // Obtiene el AuthenticationManager desde la configuración
    }

    /**
     * Bean que configura los filtros de seguridad y las reglas de autorización para las rutas de la API.
     *
     * @param http El objeto HttpSecurity que se utiliza para configurar las reglas de seguridad.
     * @return Un objeto de tipo SecurityFilterChain que contiene la configuración de seguridad.
     * @throws Exception Si ocurre algún error durante la configuración de seguridad.
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(
                        auth -> auth
                                // Permite el acceso sin autenticación a las rutas públicas
                                .requestMatchers(HttpMethod.GET, "/api/**").permitAll()
                                .requestMatchers(HttpMethod.POST, "/login").permitAll()
                                .requestMatchers(HttpMethod.POST, "/api/admins").permitAll()
                                .requestMatchers(HttpMethod.GET, "/v2/materias").permitAll()
                                .requestMatchers(HttpMethod.GET, "/v2/materias/{id}").permitAll()
                                .requestMatchers(HttpMethod.POST, "/v2/materias").permitAll()
                                .requestMatchers(HttpMethod.PUT, "/v2/materias/{id}").permitAll()
                                .requestMatchers(HttpMethod.PUT, "/v2/materias/desactivar/{id}").permitAll()
                                .requestMatchers(HttpMethod.PUT, "/v2/materias/activar/{id}").permitAll()
                                .requestMatchers(HttpMethod.GET, "/v1/grupos").permitAll()
                                .requestMatchers(HttpMethod.POST, "/v4/docente").permitAll()
                                .requestMatchers(HttpMethod.GET, "/v4/docente").permitAll()
                                .requestMatchers(HttpMethod.PUT, "/v4/docente/{id}").permitAll()
                                .requestMatchers(HttpMethod.POST, "/v1/grupos").permitAll()
                                .requestMatchers(HttpMethod.GET, "/v3/alumnos").permitAll()
                                .requestMatchers(HttpMethod.POST, "/api/**").permitAll()
                                .requestMatchers(HttpMethod.PUT, "/api/**").permitAll()
                                // Requiere autenticación para ciertas rutas
                                .requestMatchers(HttpMethod.PUT, "/api/**").authenticated()
                                // Requiere un rol específico para acceder a ciertas rutas
                                .requestMatchers(HttpMethod.PUT, "/api/*").hasAnyRole("Docente", "Alumno")
                                .anyRequest().authenticated()) // Todas las demás rutas requieren autenticación
                // Añade los filtros JWT para la autenticación y validación de tokens
                .addFilter(new JwtAuthenticationFilter(authenticationManager(), tokenJwtConfig,"/login"))
                .addFilter(new JwtValidationFilter(authenticationManager(), tokenJwtConfig))
                // Desactiva la protección CSRF (recomendado para APIs REST)
                .csrf(AbstractHttpConfigurer::disable)
                // Configura la política de sesiones a estateless (sin mantener sesiones entre peticiones)
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configura CORS para permitir el acceso desde el dominio permitido
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .build();
    }

    /**
     * Bean que configura las opciones de CORS para permitir solicitudes desde dominios específicos.
     *
     * @return Un objeto de tipo CorsConfigurationSource que define las reglas de CORS.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("http://localhost:4200")); // Permite solicitudes desde localhost:4200 (puerto de desarrollo Angular)
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE")); // Permite los métodos HTTP GET, POST, PUT y DELETE
        config.setAllowedHeaders(List.of("Authorization", "Content-Type")); // Permite ciertos encabezados
        config.setExposedHeaders(List.of("Content-Disposition")); // Expone el encabezado Content-Disposition
        config.setAllowCredentials(true); // Permite el envío de cookies y credenciales
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); // Aplica la configuración CORS a todas las rutas
        return source;
    }

    /**
     * Bean que registra un filtro de CORS con alta prioridad.
     *
     * @return Un objeto de tipo FilterRegistrationBean configurado para manejar CORS.
     */
    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter(){
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource()));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE); // Establece el filtro de CORS con la mayor prioridad
        return bean;
    }

    // Método para pruebas de codificación de contraseñas utilizando BCrypt.
    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        System.out.println(bCryptPasswordEncoder.encode("123")); // Muestra la contraseña "123" codificada con BCrypt
    }
}

package com.example.PaseListaApi.auth.service;

import com.example.PaseListaApi.auth.model.AuthDetails;
import com.example.PaseListaApi.model.user_info.User_infoRepository;
import com.example.PaseListaApi.model.user_info.Users_info;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Servicio que implementa la interfaz UserDetailsService de Spring Security.
 * Se utiliza para cargar los detalles del usuario desde la base de datos al autenticarse.
 */
@Service
public class AuthDetailsService implements UserDetailsService {

    // Repositorio para acceder a la información de los usuarios en la base de datos.
    private final User_infoRepository user_infoRepository;

    /**
     * Constructor para inyectar el repositorio de usuarios.
     * @param user_infoRepository Repositorio para gestionar los datos de los usuarios.
     */
    public AuthDetailsService(User_infoRepository user_infoRepository) {
        this.user_infoRepository = user_infoRepository;
    }

    /**
     * Método que carga los detalles del usuario por su nombre de usuario (correo electrónico en este caso).
     * @param username Nombre de usuario (correo) proporcionado durante la autenticación.
     * @return Un objeto UserDetails con la información del usuario.
     * @throws UsernameNotFoundException Si no se encuentra el usuario en la base de datos.
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Busca el usuario en la base de datos utilizando el correo electrónico.
        Users_info userAccount = user_infoRepository.findByEmail(username);

        // Si no se encuentra el usuario, lanza una excepción.
        if (userAccount == null) {
            throw new UsernameNotFoundException(username); // Error: Usuario no encontrado.
        }

        // Devuelve un objeto AuthDetails que encapsula los datos del usuario.
        return new AuthDetails(userAccount);
    }
}

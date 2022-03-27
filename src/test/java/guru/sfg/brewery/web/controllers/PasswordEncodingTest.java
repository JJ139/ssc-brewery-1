package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.util.DigestUtils;

public class PasswordEncodingTest {

    static final String PASSWORD = "password";
    static final String PASSWRD = "passwrd";

    @Test
    void hashingExample() {
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWRD.getBytes()));


        String salted = PASSWORD + "ThisIsMySALTVALUE";

        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));


    }
}

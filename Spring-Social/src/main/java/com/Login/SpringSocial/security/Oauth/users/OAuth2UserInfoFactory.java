package com.Login.SpringSocial.security.Oauth.users;


import com.Login.SpringSocial.exception.OAuth2AuthenticationProcessingException;
import com.Login.SpringSocial.model.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        }else {
            try {
                throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
            } catch (OAuth2AuthenticationProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
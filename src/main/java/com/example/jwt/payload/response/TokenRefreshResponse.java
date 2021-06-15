package com.example.jwt.payload.response;

import lombok.Data;

import javax.annotation.sql.DataSourceDefinitions;

@Data
public class TokenRefreshResponse {


    private String refreshToken;
    private String accessToken;
    private String tokenType="Bearer";


    public TokenRefreshResponse(String refreshToken, String accessToken){

        this.refreshToken = refreshToken;
        this.accessToken = accessToken;

    }

}

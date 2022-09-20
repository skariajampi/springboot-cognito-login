package com.skaria.aws.cognito;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class UsersService {

    public static final String HMAC_SHA_256 = "HmacSHA256";
    @Value(value = "${aws.cognito.userPoolId}")
    private String userPoolId;

    @Value(value = "${aws.cognito.clientId}")
    private String clientId;

    @Value(value = "${aws.cognito.secret}")
    private String clientSecret;

    @Value(value = "${aws.cognito.region}")
    private String region;

    @Value(value = "${aws.access-key}")
    private String accessKey;

    @Value(value = "${aws.access-secret}")
    private String secretKey;


    public UserLoginResponsePayload processLogin(UserLoginRequestPayload userLoginRequestPayload)
            throws Exception {

        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);

        AWSCognitoIdentityProvider cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds)).withRegion(region).build();

        UserLoginResponsePayload userLoginResponsePayload = new UserLoginResponsePayload();

        final Map<String, String> authParams = new HashMap<>();
        String clientSecretHashed = calculateSecretHash(clientId,
                clientSecret,
                userLoginRequestPayload.getUserName());

        authParams.put("USERNAME", userLoginRequestPayload.getUserName());
        authParams.put("PASSWORD", userLoginRequestPayload.getPassword());
        authParams.put("SECRET_HASH", clientSecretHashed);

        final InitiateAuthRequest authRequest = new InitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.USER_PASSWORD_AUTH).withClientId(clientId)
                .withAuthParameters(authParams);

        try {

            InitiateAuthResult result = cognitoClient.initiateAuth(authRequest);

            AuthenticationResultType authenticationResult = null;


            authenticationResult = result.getAuthenticationResult();

            userLoginResponsePayload.setAccessToken(authenticationResult.getAccessToken());
            userLoginResponsePayload.setRefreshToken(authenticationResult.getRefreshToken());
            cognitoClient.shutdown();

            return userLoginResponsePayload;

        } catch (InvalidParameterException e) {
            cognitoClient.shutdown();
            throw new Exception(e.getErrorMessage());
        } catch (Exception e) {
            cognitoClient.shutdown();
            throw new Exception(e.getMessage());
        }

    }

    public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName) {
        final String HMAC_SHA256_ALGORITHM = HMAC_SHA_256;

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(userName.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }



}
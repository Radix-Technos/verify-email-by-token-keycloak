package simonassi.keycloak.admin;

import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import simonassi.keycloak.admin.models.SimpleMessageModel;
import simonassi.keycloak.admin.requests.sendTokenToUserRequest;
import simonassi.keycloak.admin.responses.IsValidTokenResponse;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class VerifyEmailByTokenResource {

    KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;

    private final String ATT_VALIDATION_TOKEN_NAME = "validationToken";

    public VerifyEmailByTokenResource(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    @POST
    @Path("send")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendTokenToUser(sendTokenToUserRequest request) {

        UserModel currentUser = this.session.users()
                .getUserByEmail(this.session.getContext().getRealm(),
                        request.getEmail());

        if(currentUser == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(new SimpleMessageModel("User not found"))
                    .build();
        }

        Random random = new Random();
        String validationToken = String.valueOf(random.nextInt(90000) + 10000);

        currentUser.setAttribute(ATT_VALIDATION_TOKEN_NAME, Collections.singletonList(validationToken));

        try{
            sendCodeByEmail(currentUser, validationToken);
            return Response.status(Response.Status.OK)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(new SimpleMessageModel("E-mail sent with success!"))
                    .build();

        }catch (EmailException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(new SimpleMessageModel("Failed to send email: " + e.getMessage()))
                    .build();
        }
    }

    @GET
    @Path("validate")
    @Produces({MediaType.APPLICATION_JSON})
    public Response isValidToken(
            @QueryParam("token") String token,
            @QueryParam("email") String email
    ) {

        UserModel currentUser = this.session.users()
                .getUserByEmail(this.session.getContext().getRealm(), email);

        if(currentUser == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(new SimpleMessageModel("User not found"))
                    .build();
        }

        String savedToken = currentUser.getFirstAttribute(ATT_VALIDATION_TOKEN_NAME);

        if(savedToken == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(new SimpleMessageModel("You need to request a token first"))
                    .build();
        }

        if(!savedToken.equals(token)) {
            return Response.status(Response.Status.OK)
                    .header("Access-Control-Allow-Origin", "*")
                    .entity(new IsValidTokenResponse(false))
                    .build();
        }

        currentUser.removeAttribute(ATT_VALIDATION_TOKEN_NAME);
        return Response.status(Response.Status.OK)
                .header("Access-Control-Allow-Origin", "*")
                .entity(new IsValidTokenResponse(true))
                .build();
    }

    private void sendCodeByEmail(UserModel user, String code) throws EmailException {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);

        try {
            session.getProvider(EmailTemplateProvider.class)
                    .setRealm(session.getContext().getRealm())
                    .setUser(user)
                    .send("emailVerificationSubject", "email-verification-with-code.ftl", attributes);

        } catch (EmailException e) {
            // Keycloak 26 (angus-mail) propagates SocketTimeoutException from transport.close()
            // even after the message has been delivered. Treat close-only timeouts as success.
            if (isCloseTimeoutOnly(e))
                return;
            
            throw new EmailException("Error sending email", e);
        }
    }

    private boolean isCloseTimeoutOnly(EmailException e) {
        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof SocketTimeoutException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }
}

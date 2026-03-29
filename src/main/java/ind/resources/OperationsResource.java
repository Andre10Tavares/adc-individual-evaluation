package ind.resources;

import java.util.Date;
import java.util.List;
import java.util.Calendar;
import java.util.ArrayList;
import java.util.logging.Logger;
import java.util.HashMap;
import java.util.Map;


import ind.util.*;
import ind.responses.*;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;

import jakarta.servlet.http.HttpServletRequest;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.StringValue;
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.StructuredQuery.OrderBy;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;

import com.google.gson.Gson;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
@Consumes(MediaType.APPLICATION_JSON)
public class OperationsResource {
    private static final String INVALID_CREDENTIALS = "The username-password pair is not valid";
    private static final String USER_ALREADY_EXISTS = "Error in creating an account because the username already exists";
    private static final String USER_NOT_FOUND = "The username referred in the operation doesn’t exist in registered accounts";
    private static final String INVALID_TOKEN = "The operation is called with an invalid token (wrong format for example)";
    private static final String TOKEN_EXPIRED = "The operation is called with a token that is expired";
    private static final String UNAUTHORIZED = "The operation is not allowed for the user role";
    private static final String INVALID_INPUT = "The call is using input data not following the correct specification";
    private static final String FORBIDDEN = "The operation generated a forbidden error by other reason";

    private static final int ERROR_INVALID_CREDENTIALS = 9900;
    private static final int ERROR_USER_ALREADY_EXISTS = 9901;
    private static final int ERROR_USER_NOT_FOUND = 9902;
    private static final int ERROR_INVALID_TOKEN = 9903;
    private static final int ERROR_TOKEN_EXPIRED = 9904;
    private static final int ERROR_UNAUTHORIZED = 9905;
    private static final int ERROR_INVALID_INPUT = 9906;
    private static final int ERROR_FORBIDDEN = 9907;

    private static final String LOG_MESSAGE_REGISTER_ATTEMP =  "Attempt to register user: ";
    private static final String LOG_MESSAGE_REGISTER_SUCCESSFUL = "User registered: ";
    private static final String LOG_MESSAGE_REGISTER_ERROR = "Error registering user: ";
    private static final String LOG_MESSAGE_LOGIN_ATTEMP = "Login attempt by user: ";
    private static final String LOG_MESSAGE_LOGIN_UNKNOWN_USER = "Failed login attempt for username: ";
    private static final String LOG_MESSAGE_LOGIN_ERROR = "Error login user: ";
    private static final String LOG_MESSAGE_WRONG_PASSWORD = "Wrong password for: ";
    private static final String LOG_MESSAGE_LOGIN_SUCCESSFUL = "Login successful by user: ";
    private static final String LOG_MESSAGE_SHOWUSERS_ATTEMP = "Show users attempt by user: ";
    private static final String LOG_MESSAGE_SHOWUSERS_ERROR = "Error show users: ";
    private static final String LOG_MESSAGE_SHOWUSERS_UNKNOWN_TOKEN = "Failed show users attempt for token: ";
    private static final String LOG_MESSAGE_EXPIRED_TOKEN = "Expired token: ";
    private static final String LOG_MESSAGE_WRONG_ROLE = "User does not have the necessary role: ";
    private static final String LOG_MESSAGE_SHOWUSERS_SUCCESSFUL = "Show users successful by user: ";


    private static final Logger LOG = Logger.getLogger(OperationsResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
    private static final KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");

    private final Gson gson = new Gson();

    public OperationsResource() {}

    //Private op
    private Response successHandler(Object data) {
        StandardResponse response = new StandardResponse("success", data);
        return Response.ok().entity(gson.toJson(response)).build();
    }
    private Response errorHandler(int nError, String msgError) {
        StandardResponse response = new StandardResponse(nError, msgError);
        return Response.ok().entity(gson.toJson(response)).build();
    }

    private boolean checkToken(Transaction txn, Entity token, AuthToken sentToken) {
        boolean check = true;
        if (token == null) {
            check = false;
        } else {
            Key userKey = userKeyFactory.newKey(token.getString("username"));
            Entity user = txn.get(userKey);
            if (user == null ||
                    !user.getKey().getName().equals(sentToken.username) ||
                    !user.getString("role").equalsIgnoreCase(sentToken.role) ||
                    token.getLong("issuedAt") != sentToken.issuedAt ||
                    token.getLong("expiresAt") != sentToken.expiresAt) {
                check = false;
            }
        }
        return check;
    }

    private boolean checkTokenTime(Entity token) {
        long time = System.currentTimeMillis() / 1000;
        return token.getLong("expiresAt") > time;
    }

    private boolean checkRole(Entity token, List<String> expectedRoles) {
        return expectedRoles.contains(token.getString("role"));
    }
    //Private op

    //Operation 1: Create Accounts
    @POST
    @Path("/createaccount")
    public Response createAccounts(AuthData data) {
        LOG.fine(LOG_MESSAGE_REGISTER_ATTEMP + data.input.username);
        CreateAccountData newAccount = new CreateAccountData(data.input.username, data.input.password, data.input.confirmation, data.input.phone, data.input.address, data.input.role) ;
        if (!newAccount.validRegistration()) {
            return errorHandler(ERROR_INVALID_INPUT, INVALID_INPUT);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key userKey = userKeyFactory.newKey(newAccount.username);
            Entity user = txn.get(userKey);
            if (user != null) {
                txn.rollback();
                return errorHandler(ERROR_USER_ALREADY_EXISTS, USER_ALREADY_EXISTS);
            }
            user = Entity.newBuilder(userKey)
                    .set("username", newAccount.username)
                    .set("password", DigestUtils.sha512Hex(newAccount.password))
                    .set("phone", newAccount.phone)
                    .set("address", newAccount.address)
                    .set("role", newAccount.role.toUpperCase())
                    .build();
            txn.put(user);
            txn.commit();
            LOG.info(LOG_MESSAGE_REGISTER_SUCCESSFUL + newAccount.username);
            CreateAccountResponse responseRegister = new CreateAccountResponse(newAccount.username, newAccount.role);
            return successHandler(responseRegister);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_REGISTER_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error registering user.").build();
        }
    }

    //Operation 2: Login
    @POST
    @Path("/login")
    public Response login(AuthData data) {
        LOG.fine(LOG_MESSAGE_LOGIN_ATTEMP + data.input.username);
        LoginData login = new LoginData(data.input.username, data.input.password);
        if (!login.notNullUsername()) {
            return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
        }
        if(!login.validLogin()) {
            return errorHandler(ERROR_INVALID_CREDENTIALS, INVALID_CREDENTIALS);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key userKey = userKeyFactory.newKey(login.username);
            Entity user = txn.get(userKey);
            if(user == null) {
                LOG.warning(LOG_MESSAGE_LOGIN_UNKNOWN_USER + login.username);
                txn.rollback();
                return errorHandler(ERROR_INVALID_CREDENTIALS, INVALID_CREDENTIALS);
            }
            if(!user.getString("password").equals(DigestUtils.sha512Hex(login.password))) {
                LOG.warning(LOG_MESSAGE_WRONG_PASSWORD + login.username);
                txn.rollback();
                return errorHandler(ERROR_INVALID_CREDENTIALS, INVALID_CREDENTIALS);
            }
            AuthToken authToken = new AuthToken(login.username, user.getString("role"));
            Key tokenKey = tokenKeyFactory.newKey(authToken.tokenId);
            Entity token = Entity.newBuilder(tokenKey)
                    .set("username", authToken.username)
                    .set("role", authToken.role)
                    .set("issuedAt", authToken.issuedAt)
                    .set("expiresAt", authToken.expiresAt)
                    .build();
            txn.put(token);
            txn.commit();
            LOG.info(LOG_MESSAGE_LOGIN_SUCCESSFUL + login.username);
            LoginResponse responseLogin = new LoginResponse(authToken);
            return successHandler(responseLogin);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_LOGIN_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error login user.").build();
        }
    }

    //Operation 3: Show users
    @POST
    @Path("/showusers")
    public Response showUsers(AuthData data) {
        LOG.fine(LOG_MESSAGE_SHOWUSERS_ATTEMP + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_SHOWUSERS_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.tokenId);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            List<String> expectedRoles = List.of("ADMIN", "BOFFICER");
            if(!checkRole(token, expectedRoles)) {
                LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("User")
                    .build();
            QueryResults<Entity> results = txn.run(query);
            List<UserInfo> users = new ArrayList<>();
            while (results.hasNext()) {
                Entity user = results.next();
                users.add(new UserInfo(user.getKey().getName(), user.getString("role")));
            }
            UsersResponse response = new UsersResponse(users);
            txn.commit();
            LOG.info(LOG_MESSAGE_SHOWUSERS_SUCCESSFUL + data.token.username);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_SHOWUSERS_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error show user.").build();
        }
    }
}

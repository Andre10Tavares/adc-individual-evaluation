package ind.resources;

import static ind.util.StringMessages.LogMessages.*;
import static ind.util.StringMessages.ResponseMessages.*;
import static ind.util.StringMessages.ErrorMessages.*;

import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;


import ind.util.*;
import ind.responses.*;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;

import com.google.gson.Gson;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
@Consumes(MediaType.APPLICATION_JSON)
public class OperationsResource {

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
                    !token.getString("role").equalsIgnoreCase(sentToken.role) ||
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
        if (!data.inputNotNull()) {
            return errorHandler(ERROR_INVALID_INPUT, INVALID_INPUT);
        }
        LOG.fine(LOG_MESSAGE_REGISTER_ATTEMPT + data.input.username);
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
        if (!data.inputNotNull()) {
            return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
        }
        LOG.fine(LOG_MESSAGE_LOGIN_ATTEMPT + data.input.username);
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
        if (!data.tokenNotNull()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        LOG.fine(LOG_MESSAGE_SHOWUSERS_ATTEMPT + data.token.username);
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
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
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

    //Operation 4: Delete account
    @POST
    @Path("/deleteaccount")
    public Response deleteAccount(AuthData data) {
        if (!data.inputAndTokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_DELETE_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        if(!data.input.validUsername()) {
            return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_DELETE_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            List<String> expectedRoles = List.of("ADMIN");
            if(!checkRole(token, expectedRoles)) {
                LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }
            Key userKey = userKeyFactory.newKey(data.input.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                LOG.warning(LOG_MESSAGE_DELETE_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
            }
            Query<Entity> tokenQuery = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .setFilter(PropertyFilter.eq("username", data.input.username))
                    .build();
            QueryResults<Entity> tokens = txn.run(tokenQuery);
            while (tokens.hasNext()) {
                txn.delete(tokens.next().getKey());
            }
            txn.delete(userKey);
            txn.commit();
            LOG.info(LOG_MESSAGE_DELETE_SUCCESSFUL + data.input.username);
            MessageResponse response = new MessageResponse(MESSAGE_DELETE);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_DELETE_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error delete account.").build();
        }
    }

    //Operation 5: Modify account attributes
    @POST
    @Path("/modaccount")
    public Response modAccount(AuthData data) {
        if (!data.inputAndTokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_MOD_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        if(!data.input.validAttributes()) {
            return errorHandler(ERROR_INVALID_INPUT, INVALID_INPUT);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_MOD_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            Key userKey = userKeyFactory.newKey(data.input.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                LOG.warning(LOG_MESSAGE_MOD_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
            }
            if (token.getString("role").equalsIgnoreCase("USER")) {
                if(!user.getKey().getName().equals(token.getString("username"))) {
                    LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                    txn.rollback();
                    return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
                }
            } else if (token.getString("role").equalsIgnoreCase("BOFFICER")) {
                if(!user.getKey().getName().equals(token.getString("username"))
                        && !user.getString("role").equalsIgnoreCase("USER")) {
                    LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                    txn.rollback();
                    return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
                }
            }
            Entity.Builder builder = Entity.newBuilder(user);
            builder.set("phone", data.input.attributes.phone);
            builder.set("address", data.input.attributes.address);
            txn.put(builder.build());
            txn.commit();
            LOG.info(LOG_MESSAGE_MOD_SUCCESSFUL + data.input.username);
            MessageResponse response = new MessageResponse(MESSAGE_MOD);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_MOD_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error mod account.").build();
        }
    }

    //Operation 6: Show Authenticated Sessions
    @POST
    @Path("/showauthsessions")
    public Response showSessions(AuthData data) {
        if (!data.tokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_SHOW_SESSIONS_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_SHOW_SESSIONS_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            List<String> expectedRoles = List.of("ADMIN");
            if(!checkRole(token, expectedRoles)) {
                LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }
            long time = System.currentTimeMillis() / 1000;
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .build();
            QueryResults<Entity> results = txn.run(query);
            List<SessionInfo> sessions = new ArrayList<>();
            while (results.hasNext()) {
                Entity tkn = results.next();
                if (tkn.getLong("expiresAt") > time) {
                    sessions.add(new SessionInfo(
                            tkn.getKey().getName(),
                            tkn.getString("username"),
                            tkn.getString("role"),
                            tkn.getLong("expiresAt")));
                }
            }
            SessionsResponse response = new SessionsResponse(sessions);
            txn.commit();
            LOG.info(LOG_MESSAGE_SHOW_SESSIONS_SUCCESSFUL + data.token.username);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_SHOW_SESSIONS_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error show authenticated sessions.").build();
        }
    }

    //Operation 7: Show user role
    @POST
    @Path("/showuserrole")
    public Response showRole(AuthData data) {
        if (!data.inputAndTokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_SHOW_ROLE_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        if(!data.input.validUsername()) {
            return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_SHOW_ROLE_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
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
            Key userKey = userKeyFactory.newKey(data.input.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                LOG.warning(LOG_MESSAGE_SHOW_ROLE_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
            }
            txn.commit();
            LOG.info(LOG_MESSAGE_SHOW_ROLE_SUCCESSFUL + data.input.username);
            UserInfo response = new UserInfo(user.getKey().getName(), user.getString("role"));
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_SHOW_ROLE_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error show user role.").build();
        }
    }

    //Operation 8: Change User Role
    @POST
    @Path("/changeuserrole")
    public Response changeRole(AuthData data) {
        if (!data.inputAndTokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_CHANGE_ROLE_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        if(!data.input.validUsername()) {
            return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
        }
        if(!data.input.validRole()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_CHANGE_ROLE_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            Key userKey = userKeyFactory.newKey(data.input.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                LOG.warning(LOG_MESSAGE_CHANGE_ROLE_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_USER_NOT_FOUND, USER_NOT_FOUND);
            }
            List<String> expectedRoles = List.of("ADMIN");
            if(!checkRole(token, expectedRoles)) {
                LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }

            Entity.Builder builderUser = Entity.newBuilder(user);
            builderUser.set("role", data.input.newRole.toUpperCase());
            Query<Entity> tokenQuery = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .setFilter(PropertyFilter.eq("username", data.input.username))
                    .build();
            QueryResults<Entity> tokens = txn.run(tokenQuery);
            while (tokens.hasNext()) {
                Entity tkn = tokens.next();
                Entity.Builder builderToken = Entity.newBuilder(tkn);
                builderToken.set("role", data.input.newRole.toUpperCase());
                txn.put(builderToken.build());
            }
            txn.put(builderUser.build());
            txn.commit();
            LOG.info(LOG_MESSAGE_CHANGE_ROLE_SUCCESSFUL + data.input.username);
            MessageResponse response = new MessageResponse(MESSAGE_CHANGE_ROLE);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_CHANGE_ROLE_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error change role.").build();
        }
    }

    //Operation 9: Change password
    @POST
    @Path("/changeuserpwd")
    public Response changePass(AuthData data) {
        if (!data.inputAndTokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_CHANGE_PASS_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        if(!data.input.validPasswordInput()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_CHANGE_PASS_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            Key userKey = userKeyFactory.newKey(data.input.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                LOG.warning(LOG_MESSAGE_CHANGE_PASS_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_INVALID_CREDENTIALS, INVALID_CREDENTIALS);
            }
            if(!user.getKey().getName().equals(data.token.username)){
                LOG.warning(LOG_MESSAGE_CHANGE_PASS_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }
            if(!user.getString("password").equals(DigestUtils.sha512Hex(data.input.oldPassword))) {
                LOG.warning(LOG_MESSAGE_CHANGE_PASS_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_INVALID_CREDENTIALS, INVALID_CREDENTIALS);
            }
            Entity.Builder builder = Entity.newBuilder(user);
            builder.set("password", DigestUtils.sha512Hex(data.input.newPassword));
            txn.put(builder.build());
            txn.commit();
            LOG.info(LOG_MESSAGE_CHANGE_PASS_SUCCESSFUL + data.input.username);
            MessageResponse response = new MessageResponse(MESSAGE_CHANGE_PASS);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_CHANGE_PASS_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error change password.").build();
        }
    }

    //Operation 10: Logout
    @POST
    @Path("/logout")
    public Response logout(AuthData data) {
        if (!data.inputAndTokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_LOGOUT_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        if(!data.input.validUsername()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_LOGOUT_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            Key userKey = userKeyFactory.newKey(data.input.username);
            Entity user = txn.get(userKey);
            if (user == null) {
                LOG.warning(LOG_MESSAGE_LOGOUT_UNKNOWN_USER + data.input.username);
                txn.rollback();
                return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
            }
            List<String> expectedRoles = List.of("ADMIN");
            if (!checkRole(token, expectedRoles) && !token.getString("username").equals(data.input.username)) {
                LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }
            if (checkRole(token, expectedRoles) && !token.getString("username").equals(data.input.username)) {
                Query<Entity> tokenQuery = Query.newEntityQueryBuilder()
                        .setKind("Token")
                        .setFilter(PropertyFilter.eq("username", data.input.username))
                        .build();
                QueryResults<Entity> tokens = txn.run(tokenQuery);
                if (!tokens.hasNext()) {
                    LOG.warning(LOG_MESSAGE_LOGOUT_NO_LOGINS + data.input.username);
                    txn.rollback();
                    return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
                }
                while (tokens.hasNext()) {
                    txn.delete(tokens.next().getKey());
                }
            } else {
                txn.delete(tokenKey);
            }
            txn.commit();
            LOG.info(LOG_MESSAGE_LOGOUT_SUCCESSFUL + data.input.username);
            MessageResponse response = new MessageResponse(MESSAGE_LOGOUT);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_LOGOUT_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error logout account.").build();
        }
    }

    //Operation 11: Clean Expired Tokens
    @POST
    @Path("/cleantokens")
    public Response cleanTokens(AuthData data) {
        if (!data.tokenNotNull()) {
            return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
        }
        LOG.fine(LOG_MESSAGE_CLEAN_TOKENS_ATTEMPT + data.token.username);
        if(!data.token.validTokenInput()) {
            return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key tokenKey = tokenKeyFactory.newKey(data.token.tokenId);
            Entity token = txn.get(tokenKey);
            if(!checkToken(txn, token, data.token)) {
                LOG.warning(LOG_MESSAGE_CLEAN_TOKENS_UNKNOWN_TOKEN + data.token.tokenId);
                txn.rollback();
                return errorHandler(ERROR_INVALID_TOKEN, INVALID_TOKEN);
            }
            if(!checkTokenTime(token)) {
                LOG.warning(LOG_MESSAGE_EXPIRED_TOKEN + data.token.username);
                txn.delete(tokenKey);
                txn.commit();
                return errorHandler(ERROR_TOKEN_EXPIRED, TOKEN_EXPIRED);
            }
            List<String> expectedRoles = List.of("ADMIN");
            if(!checkRole(token, expectedRoles)) {
                LOG.warning(LOG_MESSAGE_WRONG_ROLE + data.token.username);
                txn.rollback();
                return errorHandler(ERROR_UNAUTHORIZED, UNAUTHORIZED);
            }
            long time = System.currentTimeMillis() / 1000;
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .setFilter(PropertyFilter.lt("expiresAt", time))
                    .build();
            QueryResults<Entity> tokens = txn.run(query);
            if (!tokens.hasNext()) {
                LOG.warning(LOG_MESSAGE_CLEAN_TOKENS_NO_TOKENS);
                txn.rollback();
                return errorHandler(ERROR_FORBIDDEN, FORBIDDEN);
            }
            while (tokens.hasNext()) {
                txn.delete(tokens.next().getKey());
            }
            MessageResponse response = new MessageResponse(MESSAGE_CLEAN_TOKENS);
            txn.commit();
            LOG.info(LOG_MESSAGE_CLEAN_TOKENS_SUCCESSFUL + data.token.username);
            return successHandler(response);
        } catch (Exception e) {
            LOG.severe(LOG_MESSAGE_CLEAN_TOKENS_ERROR + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error clean tokens.").build();
        }
    }
}

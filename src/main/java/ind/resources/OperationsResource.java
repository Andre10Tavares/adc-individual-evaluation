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
    //Private op

    //Operation 1: Create Accounts
    @POST
    @Path("/createaccount")
    public Response createAccounts(CreateAccountData data) {
        LOG.fine("Attempt to register user: " + data.username);
        if (!data.validRegistration()) {
            return errorHandler(ERROR_INVALID_INPUT, INVALID_INPUT);
        }
        try {
            Transaction txn = datastore.newTransaction();
            Key userKey = userKeyFactory.newKey(data.username);
            Entity user = txn.get(userKey);
            if (user != null) {
                txn.rollback();
                return errorHandler(ERROR_USER_ALREADY_EXISTS, USER_ALREADY_EXISTS);
            }
            user = Entity.newBuilder(userKey)
                    .set("username", data.username)
                    .set("password", DigestUtils.sha512Hex(data.password))
                    .set("phone", data.phone)
                    .set("address", data.address)
                    .set("role", data.role.toUpperCase())
                    .build();
            txn.put(user);
            txn.commit();
            LOG.info("User registered " + data.username);
            CreateAccountResponse responseData = new CreateAccountResponse(data.username, data.role);
            return successHandler(responseData);
        } catch (Exception e) {
            LOG.severe("Error registering user: " + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error registering user.").build();
        }
    }
}

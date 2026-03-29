package ind.responses;

import ind.util.UserInfo;
import java.util.List;

public class UsersResponse {

    public List<UserInfo> users;

    public UsersResponse(){}

    public UsersResponse(List<UserInfo> users) {
        this.users = users;
    }

}

package ind.responses;

import ind.util.SessionInfo;
import java.util.List;
public class SessionsResponse {

    public List<SessionInfo> sessions;

    public SessionsResponse(){}

    public SessionsResponse(List<SessionInfo> sessions) {
        this.sessions = sessions;
    }
}

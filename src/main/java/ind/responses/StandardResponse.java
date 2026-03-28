package ind.responses;

public class StandardResponse {

    public String status;
    public Object data;

    public StandardResponse(){}

    public StandardResponse(String status, Object data){
        this.status = status;
        this.data = data;
    }

    public StandardResponse(int errorNumber, String msg) {
        this.status = String.valueOf(errorNumber);
        this.data = msg;
    }
}

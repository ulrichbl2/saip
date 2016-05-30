package cs.saip.ipc.http;

import com.google.gson.Gson;
import com.mashape.unirest.http.*;
import com.mashape.unirest.http.exceptions.UnirestException;

import cs.saip.broker.*;

/**
 * ClientRequestHandler implementation using HTTP as pure IPC aka URI Tunneling.
 * Based upon the Unirest framework.
 * 
 * @author Henrik Baerbak Christensen, Computer Science, Aarhus University
 *
 */
public class UriTunnelClientRequestHandler implements ClientRequestHandler {

  private Gson gson;
  private String baseURL;

  public UriTunnelClientRequestHandler(String hostname, int port) {
    baseURL = "http://"+hostname+":"+port+"/";
    gson = new Gson();
  }

  @Override
  public ReplyObject sendToServer(String objectId, String operationName, String accessToken, String payload) {
    HttpResponse<JsonNode> jsonResponse = null;
    ReplyObject reply = null;
    
    // The payload does NOT include operationName and as we use HTTP
    // as a pure transport protocol, we need to create a more complete
    // request object which includes the full set of data required
    RequestObject request = new RequestObject(objectId, operationName, payload);
    String requestAsJson = gson.toJson(request);
    
    // All calls are URI tunneled through a POST message
    String path = Constants.BLOODPRESSURE_PATH;
    try {
      jsonResponse = Unirest.post(baseURL + path)
          .header("accept", Constants.APPLICATION_JSON)
          .header("Content-type", Constants.APPLICATION_JSON)
          .body(requestAsJson).asJson();
    } catch (UnirestException e) {
      throw new IPCException("UniRest POST request failed on objectId="
          + objectId + ", operationName=" + operationName, e);
    }
    
    String body = jsonResponse.getBody().toString();
    reply = gson.fromJson(body, ReplyObject.class);
    return reply;
  }

}

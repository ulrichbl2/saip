package cs.saip.appserver;

import java.util.*;

import com.google.gson.*;

import cs.saip.broker.*;
import cs.saip.common.OperationNames;
import cs.saip.domain.*;
import cs.saip.storage.XDSException;

/** 
 * Implementation of the Invoker role that uses JSON
 * (and the Gson library) for marshaling.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class StandardJSONInvoker implements Invoker {

  private TeleMed teleMed;
  private Gson gson;

  public StandardJSONInvoker(TeleMed teleMedServant) {
    teleMed = teleMedServant;
    gson = new Gson();
  }

  @Override
  public ReplyObject handleRequest(String objectId, String operationName, String accessToken, String payloadJSONArray) {
    ReplyObject reply = null;

    /*
     * To support multiple argument methods the parameters are mashaled into a
     * JSONArray of potentially mixed types. This is a bit complex to demarshal,
     * please review the Gson docs + example (RawCollectionsExample) which is
     * the method used here.
     */

    // Demarshal parameters into a JsonArray
    JsonParser parser = new JsonParser();
    JsonArray array = parser.parse(payloadJSONArray).getAsJsonArray();
    
    try {
      // Dispatching on all known operations
      // Each dispatch follows the same algorithm
      // a) retrieve parameters from json array (if any)
      // b) invoke servant method
      // c) populate a reply object with return values

      if (operationName.equals(OperationNames.PROCESS_AND_STORE_OPERATION)) {
        // Parameter convention: [0] = TeleObservation
        TeleObservation ts = gson.fromJson(array.get(0), TeleObservation.class);

        String uid = teleMed.processAndStore(ts, accessToken);
        reply = new ReplyObject(201, gson.toJson(uid));

      } else if (operationName.equals(OperationNames.GET_OBSERVATIONS_FOR_OPERATION)) {
        // Parameter convention: [0] = time interval
        TimeInterval interval = gson.fromJson(array.get(0), TimeInterval.class);

        List<TeleObservation> tol = teleMed.getObservationsFor(objectId, interval, accessToken);
        int statusCode = (tol == null || tol.size() == 0) ? 404 : 200;
        reply = new ReplyObject(statusCode, gson.toJson(tol));

      } else if (operationName.equals(OperationNames.CORRECT_OPERATION)) {
        // Parameter convention: [0] = tele observation
        TeleObservation to = gson.fromJson(array.get(0), TeleObservation.class);

        boolean isValid = teleMed.correct(objectId, to, accessToken);
        reply = new ReplyObject(200, gson.toJson(isValid));

      } else if (operationName.equals(OperationNames.GET_OBSERVATION_OPERATION)) {
        // Parameter: none

        TeleObservation to = teleMed.getObservation(objectId, accessToken);
        int statusCode = (to == null) ? 404 : 200;
        reply = new ReplyObject(statusCode, gson.toJson(to));

      } else if (operationName.equals(OperationNames.DELETE_OPERATION)) {
        // Parameter: none

        boolean isValid = teleMed.delete(objectId, accessToken);
        reply = new ReplyObject(200, gson.toJson(isValid));
        // More correctly, it should be 204: no contents, but most HTTP
        // libraries will then not send any payload, breaking the
        // requestor code...

      } else {
        // Unknown operation
        reply = new ReplyObject(501, "Server received unknown operation name: '"+operationName+"'.");
      }

    } catch( XDSException e ) {
      reply = new ReplyObject(500, e.getMessage());
    }
    return reply;
  }

}

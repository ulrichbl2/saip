package cs.saip.client;

import java.lang.reflect.Type;
import java.util.*;

import com.google.gson.reflect.*;

import cs.saip.broker.*;
import cs.saip.common.OperationNames;
import cs.saip.domain.*;

/**
 * The Client Proxy implementation of the TeleMed role. This surrogate object
 * resides on the client side and acts as a TeleMed instance, but all method
 * calls are marshaled and sent to the server, and the replies are interpreted
 * before returning to the callers.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class TeleMedProxy implements TeleMed, ClientProxy {

  private Requestor requestor;

  public TeleMedProxy(Requestor crh) {
    this.requestor = crh;
  }

  @Override
  public String processAndStore(TeleObservation teleObs, String accessToken) {
    String uid = requestor.sendRequestAndAwaitReply(teleObs.getPatientId(), 
        OperationNames.PROCESS_AND_STORE_OPERATION, String.class, accessToken, teleObs);
    return uid; 
  }

  @Override
  public List<TeleObservation> getObservationsFor(String patientId, TimeInterval interval, String accessToken) {
    Type collectionType = new TypeToken<List<TeleObservation>>(){}.getType();
    return requestor.sendRequestAndAwaitReply(patientId,
        OperationNames.GET_OBSERVATIONS_FOR_OPERATION, collectionType, accessToken, interval);
  }

  @Override
  public boolean correct(String uniqueId, TeleObservation to, String accessToken) {
    return requestor.sendRequestAndAwaitReply(uniqueId, 
        OperationNames.CORRECT_OPERATION, boolean.class, accessToken, to);
  }

  @Override
  public TeleObservation getObservation(String uniqueId, String accessToken) {
    return requestor.sendRequestAndAwaitReply(uniqueId, 
        OperationNames.GET_OBSERVATION_OPERATION, TeleObservation.class, accessToken);
  }

  @Override
  public boolean delete(String uniqueId, String accessToken) {
    return requestor.sendRequestAndAwaitReply(uniqueId, 
        OperationNames.DELETE_OPERATION, boolean.class, accessToken);
  }
}

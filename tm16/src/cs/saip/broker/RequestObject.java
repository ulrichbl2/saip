package cs.saip.broker;

/**
 * Request object, a record type that defines the data defining a request. As
 * this format is close to the on-the-wire format, marshaling and demarshaling
 * is pretty straight forward.
 * 
 * @author Henrik Baerbak Christensen, Computer Science, Aarhus University
 *
 */
public class RequestObject {

  private String operationName;
  private String payload;
  private String objectId;

  public RequestObject( String objectId, String operationName, String payload) {
    this.objectId = objectId;
    this.operationName = operationName;
    this.payload = payload;
  }

  public String getOperationName() {
    return operationName;
  }

  public String getPayload() {
    return payload;
  }

  public String getObjectId() {
    return objectId;
  }

}

package cs.saip.broker;

import javax.servlet.http.HttpServletResponse;

/**
 * Reply object encapsulates the reply from the server - a status code (we reuse
 * the HTTP status codes as they already define a standardized set of codes), a
 * potential error description elaborating the status code, and in case the
 * reply is a valid reply from the server, a payload which is the text returned
 * from the server.
 * <p>
 * The payload needs to be demarshaled by the Requestor to convert it into
 * domain objects and types.
 * 
 * @author Henrik Baerbak Christensen, Computer Science, Aarhus University
 *
 */
public class ReplyObject {

  private String payload;
  private String errorDescription;
  private int statusCode;

  /**
   * Create a reply with the given status code. If the status code represents a
   * valid reply, the description is assigned to the payload, otherwise it is
   * assigned to the error description.
   * 
   * @param statusCode
   *          HTTP status code of the reply
   * @param description
   *          associated text, either the payload or the error description
   */
  public ReplyObject(int statusCode, String description) {
    this.statusCode = statusCode;
    payload = errorDescription = null;
    if (isSuccess())
      payload = description;
    else
      errorDescription = description;
  }

  public boolean isSuccess() {
    return statusCode == HttpServletResponse.SC_OK 
        || statusCode == HttpServletResponse.SC_CREATED
        || statusCode == HttpServletResponse.SC_NOT_FOUND;
  }

  public String getPayload() {
    return payload;
  }

  public String errorDescription() {
    return errorDescription;
  }

  public int getStatusCode() {
    return statusCode;
  }
  
  @Override
  public String toString() {
    return "ReplyObject [payload=" + payload + ", errorDescription=" + errorDescription + ", responseCode="
        + statusCode + "]";
  }
  
}

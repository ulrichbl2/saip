package cs.saip.broker;

/**
 * The Invoker role on the server side, responsible for demarshaling the request
 * from the client, invoke the proper method on the proper Servant(s), and return a
 * reply object that encapsulate the result of the method call.
 * 
 * <p>
 * The server request handler will call the invoker's handleRequest method after
 * having received a request on the network.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public interface Invoker {

  /**
   * Handle the incoming request.
   * @param objectId 
   *          the id of the object (in a broad sense) this request is about
   * @param operationName
   *          the name of the operation (method) to call
   * @param payload
   *          the raw payload in the request message, to be demarshaled into
   *          proper parameters 
   * 
   * @return a reply object representing the outcome of the invocation
   */
  ReplyObject handleRequest(String objectId, String operationName, String payload);
}

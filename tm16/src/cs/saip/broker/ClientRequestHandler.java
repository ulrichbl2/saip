package cs.saip.broker;

/**
 * The Client Request Handler role encapsulate all inter-process-communication
 * (IPC) on behalf of client objects. It is called by the Requestor role. It
 * communicates over the network with an associated ServerRequestHandler on the
 * server side.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public interface ClientRequestHandler {

  /**
   * Send a request, defined by an operation name and a payload (in the chosen
   * marshaling format), to the server's server request handler; await an answer
   * and return a valid reply object. The objectId can be interpreted in a broad
   * sense (not necessarily as the id of 'obj' in 'obj.operation(params)'),
   * depending upon the invoker at the server side.
   * 
   * @param objectId
   *          the id of the object (in a broad sense) this request deals with
   * @param operationName
   *          the operation to perform (=method)
   * @param payload
   *          the marshaled object representing the operation 
   * @return a reply from the remote component
   * @throws IPCException
   *           in case some error happened in the IPC
   */
  public ReplyObject sendToServer(String objectId, String operationName, String accessToken, String payload);
}

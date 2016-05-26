package cs.saip.doubles;

import cs.saip.broker.*;

/**
 * A test double implementation of the ClientRequestHandler which simply
 * forwards any calls directly to an associated invoker, thus allowing the full
 * stack of remote calls implementations to be tested without the need of real
 * IPC.
 * <p>
 * Note that no ServerRequestHandler is involved as the server side IPC is
 * 'nothing' in case of normal method calls.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class LocalMethodCallClientRequestHandler implements ClientRequestHandler {

  private Invoker invoker;
  private ReplyObject lastReply;

  public LocalMethodCallClientRequestHandler(Invoker invoker) {
    this.invoker = invoker;
  }

  @Override
  public ReplyObject sendToServer(String objectId, String operationName, String onTheWireFormat) {
    // The send to the server can be mimicked by a direct method call...
    lastReply = invoker.handleRequest(objectId, operationName, onTheWireFormat);
    return lastReply;
  }

  public ReplyObject lastReply() {
    return lastReply;
  }

}

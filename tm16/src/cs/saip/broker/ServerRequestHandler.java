package cs.saip.broker;

/**
 * The server request handler role in the Broker pattern. This is solely a
 * marker interface as it may be implemented in numerous ways depending upon
 * choice of library/framework.
 * <p>
 * Responsibility: To define a specific IPC protocol and listen to any incoming
 * network messages, and forward them to an associated Invoker instance, and
 * return any ReplyObjects from the Invoker to reply messages on the network.
 * It is associated with a ClientRequestHandler on the client side of the
 * network.
 * <p>
 * However implemented, it should always spawn thread(s) to handle incoming
 * network requests.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University.
 *
 */
public interface ServerRequestHandler {

}

package cs.saip.broker;

import java.lang.reflect.Type;

/**
 * The Requestor role on the client side, encapsulate creation (marhaling),
 * handling and sending request messages on behalf of the client proxies.
 * The Requestor sends messages using its associated ClientRequestHandler.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public interface Requestor {
  
  /**
   * Marshal the given operation and its parameters into a request object, send
   * it to the remote component, and interpret the answer and convert it back
   * into the return type of generic type T
   * 
   * @param <T>
   *          generic type of the return value
   * @param objectId
   *          the object that this request relates to; not that this may not
   *          necessarily just be the object that the method is called upon
   * @param operationName
   *          the operation (=method) to invoke
   * @param typeOfReturnValue
   *          the java reflection type of the returned type
   * @param argument
   *          the arguments to the method call
   * @return the return value of the type given by typeOfReturnValue
   */
  <T> T sendRequestAndAwaitReply(String objectId, String operationName, Type typeOfReturnValue, String accessToken, Object... argument);

}

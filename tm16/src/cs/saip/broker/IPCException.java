package cs.saip.broker;

/** The superclass of any exceptions occurring during IPC between
 * client and server.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class IPCException extends RuntimeException {

  public IPCException(String message, Throwable exception) {
    super(message, exception);
  }

  public IPCException(String message) {
    super(message);
  }

  /**
   * 
   */
  private static final long serialVersionUID = 7220436156585793897L;

}

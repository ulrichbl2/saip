package cs.saip.main;

import cs.saip.appserver.*;
import cs.saip.broker.*;
import cs.saip.domain.TeleMed;
import cs.saip.doubles.*;
import cs.saip.ipc.socket.SocketServerRequestHandler;
import cs.saip.storage.XDSBackend;

/** App server, using socket based implementations of broker roles.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class SocketServerMain {
  
  private static Thread daemon; 
  
  public static void main(String[] args) throws Exception {
    new SocketServerMain(args[0]); // No error handling!
  }
  
  public SocketServerMain(String type) throws Exception {
    // Define the server side delegates
    XDSBackend xds = null;
    xds = new FakeObjectXDSDatabase();

    TeleMed tsServant = new TeleMedServant(xds);
    Invoker invoker = new StandardJSONInvoker(tsServant);

    // Configure a socket based server request handler
    SocketServerRequestHandler ssrh = new SocketServerRequestHandler(37321, invoker);
    
    // Welcome 
    System.out.println("=== TM16 Server Request Handler ==="); 
    System.out.println(" Use ctrl-c to terminate!"); 
    
    // and start the daemon...
    daemon = new Thread(ssrh); 
    daemon.start(); 
    
    // Ensure that its lifetime follows that of the main process
    daemon.join(); 
  }
}

package cs.saip.main;

import java.util.logging.*;

import cs.saip.appserver.*;
import cs.saip.authorization.JWTAuthorizationImpl;
import cs.saip.broker.Invoker;
import cs.saip.domain.*;
import cs.saip.doubles.FakeObjectXDSDatabase;
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
    Logger logger = Logger.getLogger("TM16Logger");
    logger.addHandler(new StreamHandler(System.out, new SimpleFormatter()));
    Authorization atz = new JWTAuthorizationImpl(logger);

    TeleMed tsServant = new TeleMedServant(xds, atz);
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

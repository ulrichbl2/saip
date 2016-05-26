package cs.saip.main;

import cs.saip.appserver.*;
import cs.saip.broker.*;
import cs.saip.domain.TeleMed;
import cs.saip.doubles.*;
import cs.saip.ipc.rest.*;
import cs.saip.storage.XDSBackend;

/** Jetty/Spark-java based server responding to REST calls.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class RestServerMain {
  
  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      explainAndDie();
    }
    new RestServerMain(args[0]); // No error handling!
  }
  
  private static void explainAndDie() {
    System.out.println("Usage: RestServerMain {port}");
    System.out.println("       port = port number for server to listen to");
    System.exit(-1);
  }

  public RestServerMain(String portNo) throws Exception {
    // Define the server side delegates
    XDSBackend xds = null;
    xds = new FakeObjectXDSDatabase();
    TeleMed tsServant = new TeleMedServant(xds);

    // Configure the Spark-java servlet
    int port = Integer.parseInt(portNo);
    RESTServerRequestHandlerInvoker srh = 
        new RESTServerRequestHandlerInvoker(port, tsServant, xds);
    srh.registerRoutes();
    
    // Welcome 
    System.out.println("=== TM16 Spark based REST Server Request Handler (port:"+port+") ==="); 
    System.out.println(" Use ctrl-c to terminate!"); 
  }
}

package cs.saip.main;

import cs.saip.appserver.*;
import cs.saip.authorization.AuthorizeAllStub;
import cs.saip.broker.Invoker;
import cs.saip.domain.TeleMed;
import cs.saip.doubles.FakeObjectXDSDatabase;
import cs.saip.ipc.http.UriTunnelServerRequestHandler;
import cs.saip.storage.XDSBackend;
import cs.saip.storage.mongo.MongoXDSAdapter;

/** Jetty/Spark-java based server responding to URI Tunneled POST
 * uploads and GET requests.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class ServerMain {
  
  public static void main(String[] args) throws Exception {
    // Command line argument parsing and validation
    if (args.length < 1) {
      explainAndDie();
    }
    new ServerMain(args[0]); // No error handling!
  }
  
  private static void explainAndDie() {
    System.out.println("Usage: ServerMain {type}");
    System.out.println("       type = 'memory'|{host} indicate the type of DB to use");
    System.exit(-1);
  }

  public ServerMain(String type) throws Exception {
    int port = 4567;
    // Define the server side delegates
    XDSBackend xds = null;
    if (type.equals("memory")) {
    xds = new FakeObjectXDSDatabase();
    } else {
      xds = new MongoXDSAdapter(type, 27017);
    }
    // Create server side implementation of Broker roles
    TeleMed tsServant = new TeleMedServant(xds, new AuthorizeAllStub());
    Invoker invoker = new StandardJSONInvoker(tsServant);
    UriTunnelServerRequestHandler srh = 
        new UriTunnelServerRequestHandler(invoker, xds, port);
    srh.registerRoutes(); // This will automatically spawn a tread for the web server
      
    // Welcome
    System.out.println("=== TM16 Spark based Server Request Handler (port:"+port+", type:"+type+") ==="); 
    System.out.println(" Use ctrl-c to terminate!"); 
  }
}

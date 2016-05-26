package cs.saip.ipc.http;

import static spark.Spark.*;

import java.time.LocalDateTime;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;

import cs.saip.appserver.XMLUtility;
import cs.saip.broker.*;
import cs.saip.storage.XDSBackend;

import org.w3c.dom.Document;

/** ServerRequestHandler implementation using HTTP and URI Tunneling, as well
 * as web server for General Practitioner overview of measurements for
 * a given patient.
 * <p>
 * Implementation based on the Spark-Java framework.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University.
 *
 */
public class UriTunnelServerRequestHandler implements ServerRequestHandler {

  private Gson gson;
  private Invoker invoker;
  private int port;
  private int lastStatusCode;
  private String lastVerb;
  private XDSBackend xds;

  public UriTunnelServerRequestHandler(Invoker invoker, XDSBackend xds, int port) {
    this.invoker = invoker;
    this.xds = xds;
    this.port = port;
    gson = new Gson();
  }

  public void registerRoutes() {
    // Set the port to listen to
    port(port);
    
    String tunnelRoute = "/" + Constants.BLOODPRESSURE_PATH;
    
    // POST is for all incoming requests
    post(tunnelRoute, (req,res) -> {
      String body = req.body();
      
      // The incoming body is a full request object to be demarshaled
      RequestObject p = gson.fromJson(body, RequestObject.class);

      ReplyObject reply = invoker.handleRequest(p.getObjectId(), p.getOperationName(), p.getPayload());
      lastVerb = req.requestMethod();
      lastStatusCode = reply.getStatusCode();
      
      res.status(reply.getStatusCode());
      res.type(Constants.APPLICATION_JSON);

      return gson.toJson(reply);
    });
    
    // GET is used to access all observations for a given patient
    String getRoute = "/" + Constants.BLOODPRESSURE_PATH+ ":patientId";
    get(getRoute, (req, res) -> {
      String patientId = req.params(":patientId");
      String html = "<html><body><h1>TeleMed</h1><h2>Observations for "+patientId+"</h2>"; 

      List<Document> list;
      // Calculate the time interval to search within
      LocalDateTime now = LocalDateTime.now();
      LocalDateTime someTimeAgo = now.minusDays(7);

      list = xds.retriveDocumentSet(patientId, someTimeAgo, now);
      html += "<H3>There are "+list.size() + " observations.</H3>\n";
      for ( Document doc1 : list ) {
        html += "<hr/><pre>";
        // sigh - have to convert all < to the &lt; etc. 
        String tmp = XMLUtility.convertXMLDocumentToString(doc1);
        tmp = tmp.replaceAll("<", "&lt;");
        tmp = tmp.replaceAll(">", "&gt;");
        // System.out.println( tmp );
        html += tmp;
        html += "</pre>";
      }

      html += "</body></html>";
      
      res.status(HttpServletResponse.SC_OK);
      
      return html;
    });
    
  }

  public void closedown() {
    stop();
  }
  
  /**
   * Return status code of last operation. A test
   * retrieval interface.
   * 
   * @return last status code
   */
  public int lastStatusCode() {
    return lastStatusCode;
  }

  public String lastHTTPVerb() {
    return lastVerb;
  }

}

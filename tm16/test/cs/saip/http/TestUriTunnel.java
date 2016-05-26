package cs.saip.http;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.junit.*;

import cs.saip.appserver.*;
import cs.saip.broker.*;
import cs.saip.client.*;
import cs.saip.domain.*;
import cs.saip.doubles.FakeObjectXDSDatabase;
import cs.saip.helper.HelperMethods;
import cs.saip.ipc.http.*;

/** Test that a simple upload and fetch scenario is working
 * using the HTTP URI Tunneling variants of the Client- and
 * ServerRequestHandlers.
 * <p>
 * For reasons I have not diagnosed yet, rapid starting and
 * shutting down Spark leads to failures on Ubuntu Linux.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University.
 *
 */
public class TestUriTunnel {

  static final int PORT_NUMBER = 4567;
  
  TeleMedProxy teleMed;
  UriTunnelServerRequestHandler serverRequestHandler;

  @Before
  public void setup() {
    // Server side roles
    FakeObjectXDSDatabase xds = new FakeObjectXDSDatabase();
    TeleMed tsServant = new TeleMedServant(xds);
    StandardJSONInvoker invoker = new StandardJSONInvoker(tsServant);

    serverRequestHandler = new UriTunnelServerRequestHandler(invoker, xds, PORT_NUMBER);
    serverRequestHandler.registerRoutes();

    // Client side roles
    ClientRequestHandler restCRH = new UriTunnelClientRequestHandler("localhost", PORT_NUMBER);

    Requestor requestor = new StandardJSONRequestor(restCRH);
    teleMed = new TeleMedProxy(requestor);
  }
  
  @After
  public void teardown() {
    serverRequestHandler.closedown();
  }
  
  @Test
  public void shouldHandleScenario() {
    TeleObservation teleObs1 = new TeleObservation(HelperMethods.NANCY_CPR, 127.3, 93);
    
    // Upload
    String id2 = teleMed.processAndStore(teleObs1);
    // Verify that CREATED code was returned
    assertThat(serverRequestHandler.lastStatusCode(), is(HttpServletResponse.SC_CREATED));
    assertThat(serverRequestHandler.lastHTTPVerb(), is("POST"));
    
    assertThat(id2, is(notNullValue()));
    
    // Download
    List<TeleObservation> l = teleMed.getObservationsFor(HelperMethods.NANCY_CPR, TimeInterval.LAST_DAY);

    // Verify it is correctly fetched
    assertThat(l, is(notNullValue()));
    assertThat(l.size(), is(1));
    assertThat(l.get(0).getSystolic().getValue(), is(127.3));
  }
  
}

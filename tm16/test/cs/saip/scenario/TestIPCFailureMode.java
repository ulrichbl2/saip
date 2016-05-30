package cs.saip.scenario;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;

/** Initial tests for failure modes in IPC,
 * typically broken networks or unreachable server.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
import org.junit.*;

import cs.saip.appserver.*;
import cs.saip.authorization.AuthorizeAllStub;
import cs.saip.broker.*;
import cs.saip.client.*;
import cs.saip.domain.*;
import cs.saip.doubles.*;
import cs.saip.helper.HelperMethods;

public class TestIPCFailureMode {


  private TeleObservation teleObs1;
  private FakeObjectXDSDatabase xds;
  
  private TeleMed telemed;

  @Before 
  public void setup() {
    // Create server side implementations
    xds = new FakeObjectXDSDatabase();
    TeleMed tsServant = new TeleMedServant(xds, new AuthorizeAllStub());

    // Server side broker implementations
    Invoker invoker = new StandardJSONInvoker(tsServant);
    
    // Create client side broker implementations
    ClientRequestHandler clientRequestHandler = new LocalMethodCallClientRequestHandler(invoker);
    // Decorate it with a saboteur of the connection
    clientRequestHandler = new SaboteurRequestHandler(clientRequestHandler);
    Requestor requestor = new StandardJSONRequestor(clientRequestHandler);
    
    // Finally, create the client proxy for the TeleMed
    telemed = new TeleMedProxy(requestor);
  }

  @Test
  public void test() {
    teleObs1 = HelperMethods.createObservation120over70forNancy();
    try {
      telemed.processAndStore(teleObs1, "");
      fail("Should throw TeleMedExcpetion");
    } catch (IPCException e) {
      assertThat(e.getMessage(), containsString("nasty communication error"));
    }
  }

  public class SaboteurRequestHandler implements ClientRequestHandler {

    public SaboteurRequestHandler(ClientRequestHandler clientRequestHandler) {
      // Not really using the decoratee for anything
    }

    @Override
    public ReplyObject sendToServer(String objectId, String operationName,
        String accessToken, String payload) {
      throw new IPCException("Send failed due to nasty communication error");
    }

  }

}

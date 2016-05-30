package cs.saip.scenario;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import cs.saip.appserver.*;
import cs.saip.authentication.AuthenticationStub;
import cs.saip.authorization.AuthorizationStub;
import cs.saip.broker.*;
import cs.saip.client.*;
import cs.saip.domain.*;
import cs.saip.doubles.*;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.nimbusds.jwt.JWTClaimsSet;
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class FoxtrotTest_Auth 
{

  private Authentication authentication;
  private Authorization authorization;
  
  private String pt1AccessToken, pt2AccessToken, dt1AccessToken, dt2AccessToken, UnknownPwd1AcessToken, UnknownUserAccessToken;
  
  private FakeObjectXDSDatabase xds;
  
  private TeleMed teleMed;
  
  @Before
  public void setup()
  {
    authentication = new AuthenticationStub();
    authorization = new AuthorizationStub();
    
    // Create 2 patients and 2 doctors and 2 invalid users
    pt1AccessToken = new String();
    pt2AccessToken = new String();
    dt1AccessToken = new String();
    dt2AccessToken = new String();
    UnknownPwd1AcessToken = new String();
    UnknownUserAccessToken = new String();
    
    // Authenticate the 6 users
    authentication.authenticate("KnownPatient1", "KnownPassword"); // Patient 1
    pt1AccessToken = new AuthorizationStub().createAccessToken(authentication.getSystemName("KnownPatient1"));
    authentication.authenticate("KnownPatient2", "KnownPassword"); // Patient 2
    pt2AccessToken = new AuthorizationStub().createAccessToken(authentication.getSystemName("KnownPatient2"));
    authentication.authenticate("KnownDoctor1", "KnownPassword"); // Doctor 1
    dt1AccessToken = new AuthorizationStub().createAccessToken(authentication.getSystemName("KnownDoctor1"));
    authentication.authenticate("KnownDoctor2", "KnownPassword"); // Doctor 2
    dt2AccessToken = new AuthorizationStub().createAccessToken(authentication.getSystemName("KnownDoctor2"));
    if (authentication.authenticate("KnownDoctor2", "UnKnownPassword")) { // Doctor 2 but wrong password
      UnknownPwd1AcessToken = new AuthorizationStub().createAccessToken(authentication.getSystemName("KnownDoctor2"));
    }
    else {
      UnknownPwd1AcessToken = null;
    }
    if (authentication.authenticate("UnKnownDoctor3", "UnKnownPassword")) { // Doctor 3 = Unknown user
      UnknownUserAccessToken = new AuthorizationStub().createAccessToken(authentication.getSystemName("UnKnownDoctor3"));
    }
    else {
      UnknownUserAccessToken = null;
    }
     
    
    // Create all the other from old test
    xds = new FakeObjectXDSDatabase();
    TeleMed teleMedServant = new TeleMedServant(xds, authorization);

    // Server side broker implementations
    Invoker invoker = new StandardJSONInvoker(teleMedServant);
    
    // Create client side broker implementations
    ClientRequestHandler clientRequestHandler = new LocalMethodCallClientRequestHandler(invoker);
    Requestor requestor = new StandardJSONRequestor(clientRequestHandler);
    
    // Finally, create the client proxy for the TeleMed
    teleMed = new TeleMedProxy(requestor);
    
  }
  
  
  /* Test different kinds of login to the system: 
   *  Known username unknown password, 
   *  Know username, known password
   *  Unknown username and password
   */
  @Test
  public void Test_01_VerifyLogin()
  {
    
    // Test users that should have access
    assertThat(new AuthorizationStub().getJWTClaimsSet(pt1AccessToken).getSubject(), is("p1"));
    JWTClaimsSet js = new AuthorizationStub().getJWTClaimsSet(pt2AccessToken);
    assertThat(js.getSubject(), is("p2"));
    assertThat(new AuthorizationStub().getJWTClaimsSet(dt1AccessToken).getSubject(), is("d1"));
    assertThat(new AuthorizationStub().getJWTClaimsSet(dt2AccessToken).getSubject(), is("d2"));
    
    // Test unknown usernames / passwords.
    assertNull(new AuthorizationStub().getJWTClaimsSet(UnknownPwd1AcessToken));
    assertNull(new AuthorizationStub().getJWTClaimsSet(UnknownUserAccessToken));
  }
  
  @Test
  public void Test_02_ValidPatientSaveData()
  {
    TeleObservation teleObs = new TeleObservation("p1", 123, 78); 
    String storeId = teleMed.processAndStore(teleObs, pt1AccessToken);
    assertThat(storeId, not("-1"));
    assertThat(storeId, not(""));
  }
  @Test
  public void Test_03_ValidateDoctorFetchDataAnValidateData()
  {
    // First store some data. 
    TeleObservation teleObs = new TeleObservation("p1", 123, 78); 
    String storeId = teleMed.processAndStore(teleObs, dt1AccessToken);
    assertThat(storeId, not("-1"));
    assertThat(storeId, not(""));
    
    // Try to fetch data again for a doctor who has access to patient data
    List<TeleObservation> lastWeekList = teleMed.getObservationsFor("p1", TimeInterval.LAST_WEEK, dt1AccessToken);
    
    // Verify that data are correct
    assertThat(lastWeekList, is(notNullValue()));
    assertThat(lastWeekList.size(), is(1));
    TeleObservation obs;
    obs = lastWeekList.get(0);
    assertThat(obs.getPatientId(), is("p1"));
    assertThat(obs.getSystolic().toString(), is("Systolisk BT:123.0 mm(Hg)"));
    
    // Try to fetch data again, for a doctor who no NOT have access to patient data
    lastWeekList = teleMed.getObservationsFor("p1", TimeInterval.LAST_WEEK, dt2AccessToken);
    assertThat(lastWeekList, is(nullValue()));
  }
  @Test
  public void Test_04_ValidateDoctorFetchPatientData()
  {
    // Doctor 1 tries to get info from patient 1, which he shall be allowed to
    List<TeleObservation> lastWeekList = teleMed.getObservationsFor("p1",TimeInterval.LAST_WEEK , dt1AccessToken);
    assertThat(lastWeekList, is(notNullValue()));
    assertThat(lastWeekList.size(), is(0));
    
    // Doctor 1 tries to get info from patient 2, which he shall NOT be allowed to
    lastWeekList = teleMed.getObservationsFor("p2",TimeInterval.LAST_WEEK , dt1AccessToken);
    assertThat(lastWeekList, is(nullValue())); 
  }

}

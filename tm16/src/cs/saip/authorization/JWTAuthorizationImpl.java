package cs.saip.authorization;

import java.text.*;
import java.util.*;
import java.util.logging.Logger;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import cs.saip.domain.Utility;

public class JWTAuthorizationImpl extends AbstractAuthorization {
  private Map <String, List<String>> AuthorizationMap;
  // Hardcoded test AES-256 key - could have been dynamically created or RSA even - not important for the AP
  private static final String b64enCodedSecretKey = "WGL9etjEpH5mfC+SmgsUZOZiO7TVxcg8BZE1OTRSjq4=";
  private Logger logger;

  /**
   * Hard coded list of authorization rules - could have been a database or the like - not important for the AP
   */
  public JWTAuthorizationImpl(Logger logger)
  {
    super(logger);
    this.logger = logger;
    AuthorizationMap = new HashMap<String, List<String>>();

    AuthorizationMap.put("p1", new ArrayList<String>());
    AuthorizationMap.get("p1").add("w:p1"); // Patient token 1 can write to patient data 1

    AuthorizationMap.put("d1", new ArrayList<String>());
    AuthorizationMap.get("d1").add("w:p1"); // Doctor token 1 can write to patient data 1
    AuthorizationMap.get("d1").add("r:p1"); // Doctor token 1 can read to patient data 1

    AuthorizationMap.put("p2", new ArrayList<String>());
    AuthorizationMap.get("p2").add("w:p2"); // Patient token 2 can write to patient data 2

    AuthorizationMap.put("d2", new ArrayList<String>());
    AuthorizationMap.get("d2").add("w:p2"); // Doctor token 2 can write to patient data 2
    AuthorizationMap.get("d2").add("r:p2"); // Doctor token 2 can read to patient data 2
  }

  @Override
  public Boolean allowWritePatientData(String accessToken, String pId) throws Exception {

    // Check for write rights
    String userID = getUserID(accessToken);
    boolean granted = false;
    if (userID != null) {
      granted = CheckAccess(accessToken, pId, "w");
      String accessStatus = granted ? "GRANTED" : "DENIED";
      logger.info(Utility.convertUnixEpochToLocalDateTime(new Date().getTime()) + " : " + getUserID(accessToken) + " was " + accessStatus + " access to write data for patien id: " + pId);
      return granted;
    }
    else {
      return granted;
    }
  }

  @Override
  public Boolean allowReadPatientData(String accessToken, String pId) throws Exception {

    // Check for read rights
    String userID = getUserID(accessToken);
    boolean granted = false;
    if (userID != null) {
      granted = CheckAccess(accessToken, pId, "r");
      String accessStatus = granted ? "GRANTED" : "DENIED";
      logger.info(Utility.convertUnixEpochToLocalDateTime(new Date().getTime()) + " : " + getUserID(accessToken) + " was " + accessStatus + " access to read data for patien id: " + pId);
      return granted;
    }
    else {
      return granted;
    }
  }

  private String getUserID(String accessToken) throws Exception {
    JWTClaimsSet jss = getJWTClaimsSet(accessToken);

    if (jss != null) {
      return jss.getSubject();
    }
    else {
      logger.warning("User not found");
    }
    return null;

  }

  private Boolean CheckAccess(String accessToken, String pId, String accessToCheckFor) throws Exception
  {
    // Parse accessToken to JWT claimsset
    JWTClaimsSet jss = getJWTClaimsSet(accessToken);

    if (jss != null) {
      // Check if the accessToken is in the map
      if(AuthorizationMap.containsKey(jss.getSubject()))
      {
        // Get the access rights for the token
        Boolean read = false;
        try {
          read = jss.getBooleanClaim("r:" + pId);
        } catch (ParseException e) {
          read = false;
        }
        Boolean write = false;
        try {
          write = jss.getBooleanClaim("w:" + pId);
        } catch (ParseException e) {
          write = false;
        } 
        if (read == null)
          read = false;
        if (write == null)
          write = false;
        return (read || write);
      }
    }
    return false;
  }

  public JWTClaimsSet getJWTClaimsSet(String accessToken) throws Exception {
    JWTClaimsSet cSet = null;
    SignedJWT signedJWT = null;
    if (accessToken != null) { 
      signedJWT = verifyToken(accessToken);
      // Retrieve the JWT claims...
      return signedJWT.getJWTClaimsSet();
    }
    return cSet;
  }

  /**
   * Create basic JWT token that is signed and encrypted
   * @param id
   * @return
   */
  public String createAccessToken(String id) {
    String jweString = null;
    try {
      // Generate 256-bit AES key for HMAC as well as encryption
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);

      SecretKey secretKey = getSecretKey();
      // Create HMAC signer
      JWSSigner signer = new MACSigner(secretKey.getEncoded());

      // Prepare JWT with claims set
      Date now = new Date();
      Builder b = new JWTClaimsSet.Builder();
      b.subject(id)
      .expirationTime(new Date(now.getTime() + (10 * 1000))) // set expiration to 10 seconds (good for unit testing)
      .issueTime(now)
      .issuer("TM16")
      .notBeforeTime(now);

      // Add patien claimsset
      if (AuthorizationMap.get(id) != null) {
        for (String claim : AuthorizationMap.get(id)) {
          b.claim(claim, true);
        }
      }

      JWTClaimsSet claimsSet = b.build();

      SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

      // Apply the HMAC
      signedJWT.sign(signer);

      // Create JWE object with signed JWT as payload
      JWEObject jweObject = new JWEObject(
          new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
          .contentType("JWT") // required to signal nested JWT
          .build(),
          new Payload(signedJWT));

      // Perform encryption
      jweObject.encrypt(new DirectEncrypter(secretKey.getEncoded()));

      // Serialise to JWE compact form
      jweString = jweObject.serialize();
    } catch (Exception e) {
      logger.warning(e.getMessage());
    }
    return jweString;
  }

  private SignedJWT verifyToken(String accessToken) throws Exception {
    SignedJWT signedJWT = null;
    SecretKey secretKey = null;
    try {
      JWEObject jweObject = JWEObject.parse(accessToken);

      secretKey = getSecretKey();
      jweObject.decrypt(new DirectDecrypter(secretKey.getEncoded()));

      signedJWT = jweObject.getPayload().toSignedJWT();
    } catch (Exception e) {
      logger.warning(e.getMessage());
    }

    if (signedJWT == null) {
      throw new Exception("Payload not a signed JWT");
    }

    // Check the HMAC
    if (signedJWT.verify(new MACVerifier(secretKey.getEncoded())) == false) {
      signedJWT = null;
      throw new Exception("Mac was not verified");
    }

    // Assert that accessToken is still valid (10 seconds)
    if (signedJWT.getJWTClaimsSet().getExpirationTime().getTime() > new Date().getTime() == false) {
      signedJWT = null;
      throw new Exception("AccessToken has expired");
    }

    // Assert that time.now is not before the time-window assigned to the token
    if (new Date().getTime() > signedJWT.getJWTClaimsSet().getNotBeforeTime().getTime() == false) {
      signedJWT = null;
      throw new Exception("AccessToken is not yet valid");
    }
    return signedJWT;
  }

    private SecretKey getSecretKey() {
      // Decrypt with shared key
      byte[] encodedKey = Base64.getDecoder().decode(JWTAuthorizationImpl.b64enCodedSecretKey);
      return new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
    }

  }

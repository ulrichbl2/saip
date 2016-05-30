package cs.saip.authorization;

import static org.junit.Assert.*;

import java.text.ParseException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import cs.saip.domain.Authorization;

public class AuthorizationStub implements Authorization {
  private Map <String, List<String>> AuthorizationMap;
  // Hardcoded test AES-256 key
  private static final String b64enCodedSecretKey = "WGL9etjEpH5mfC+SmgsUZOZiO7TVxcg8BZE1OTRSjq4=";

  public AuthorizationStub()
  {
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
  public Boolean allowWritePatientData(String accessToken, String pId) {

    // Check for write rights
    return CheckAccess(accessToken, pId, "w");
  }

  @Override
  public Boolean allowReadPatientData(String id, String pId) {

    // Check for read rights
    return CheckAccess(id, pId, "r");
  }

  private Boolean CheckAccess(String accessToken, String pId, String accessToCheckFor)
  {
    // Parse accessToken to JWT claimsset
    JWTClaimsSet jss = getJWTClaimsSet(accessToken);

    // Check if the accessToken is in the map
    if(AuthorizationMap.containsKey(jss.getSubject()))
    {
      // Get the access rights for the token
      Boolean read;
      try {
        read = jss.getBooleanClaim("r:" + pId);
      } catch (ParseException e) {
        read = false;
      }
      Boolean write;
      try {
        write = jss.getBooleanClaim("w:" + pId);
      } catch (ParseException e) {
        write = false;
      } 
      return (read || write);
    }
    return false;
  }

  public JWTClaimsSet getJWTClaimsSet(String accessToken) {
    JWTClaimsSet cSet = null;
    try {
      // Decrypt and verify
      // Parse the JWE string
      if (accessToken != null) { 
        JWEObject jweObject = JWEObject.parse(accessToken);

        // Decrypt with shared key
        byte[] encodedKey = Base64.getDecoder().decode(AuthorizationStub.b64enCodedSecretKey);
        SecretKey secretKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

        jweObject.decrypt(new DirectDecrypter(secretKey.getEncoded()));

        // Extract payload
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        assertNotNull("Payload not a signed JWT", signedJWT);

        // Check the HMAC
        assertTrue(signedJWT.verify(new MACVerifier(secretKey.getEncoded())));

        // Retrieve the JWT claims...
        return signedJWT.getJWTClaimsSet();
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return cSet;
  }

  public String createAccessToken(String id) {
    String jweString = null;
    try {
      // Generate 256-bit AES key for HMAC as well as encryption
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);

      byte[] encodedKey = Base64.getDecoder().decode(AuthorizationStub.b64enCodedSecretKey);
      SecretKey secretKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

      // Create HMAC signer
      JWSSigner signer = new MACSigner(secretKey.getEncoded());

      // Prepare JWT with claims set
      Date now = new Date();
      Builder b = new JWTClaimsSet.Builder();
      b.subject(id)
      .expirationTime(new Date(now.getTime() + 4 * Calendar.HOUR)) // set expiration to 4 hours
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
      e.printStackTrace(System.out);
    }
    return jweString;
  }

}

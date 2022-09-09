package io.github.mschout.email.srs.provider;

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.SRS;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class GuardedSRSProviderTest {
  private SRS srs;

  @BeforeEach
  public void createSrs() {
    srs = new SRS(SRS.Type.GUARDED, "foo");
  }

  @Test
  public void forward() throws NoSuchAlgorithmException, InvalidKeyException {
    String addr = "user@domain-with-dash.com";

    String srs0 = srs.forward(addr, "foo.com");
    String srs1 = srs.forward(srs0, addr);

    assertTrue(srs0.startsWith("SRS0"), "Starts with SRS0");
    assertTrue(srs1.startsWith("SRS1"), "Starts with SRS1");
    assertEquals('=', srs1.charAt(4), "Separator is '='");

    assertTrue(srs0.matches("SRS0=\\S{4}=\\S{2}=domain-with-dash\\.com=user@foo.com"));
    assertTrue(srs1.matches("SRS1=\\S{4}=foo.com==\\S{4}=\\S{2}=domain-with-dash\\.com=user@domain-with-dash\\.com"));

    assertEquals(addr, srs.reverse(srs0), "SRS0 reverses to original address");
    assertEquals(srs0, srs.reverse(srs1), "SRS1 reverses to SRS0 address");
    assertEquals(addr, srs.reverse(srs.reverse(srs1)), "Reversal of reverse(srs1) is original address");
  }

  @Test
  public void reverse() throws NoSuchAlgorithmException, InvalidKeyException {
    String addr = "user@domain-with-dash.com";

    String alias0 = srs.forward(addr, "foo.com");
    String alias1 = srs.forward(alias0, addr);

    assertEquals(alias0, srs.reverse(alias1));
    assertEquals(addr, srs.reverse(alias0));
  }

  @Test
  public void usernames() throws NoSuchAlgorithmException, InvalidKeyException {
    List<String> addresses = ImmutableList.of(
      "user@domain-with-dash.com",
      "user-with-dash@domain.com",
      "user+with+plus@domain.com",
      "user%with!everything&everything=@domain.somewhere"
    );

    List<String> aliases = ImmutableList.of("user1@tld1.com", "user2@tld2.com");

    for (String email : addresses) {
      String srs0 = srs.forward(email, aliases.get(0));
      assertEquals(email, srs.reverse(srs0), "Reverses to original address");

      // idempotent on srs0addr
      String srs1 = srs.forward(srs0, aliases.get(1));
      assertEquals(srs0, srs.reverse(srs1), "SRS1 reverses to SRS0 address");

      // idempotent from same domain.
      assertEquals(srs0, srs.forward(srs0, aliases.get(0)), "Rewruite to same domain");
    }
  }

  @Test
  public void invalidHash() throws NoSuchAlgorithmException, InvalidKeyException {
    String srs0 = srs.forward("user@domain.com", "example.com");

    // Replace hash with XXXX
    final String invalidsrs = "SRS0=XXXX" + srs0.substring(srs0.indexOf('=', 8));

    Exception exception = assertThrows(IllegalArgumentException.class, () -> srs.reverse(invalidsrs));

    assertTrue(exception.getMessage().contains("Invalid address hash: XXXX"));
  }

  @Test
  public void caseSensitivity() throws NoSuchAlgorithmException, InvalidKeyException {
    List<String> addresses = ImmutableList.of(
      "User@domain-with-dash.com",
      "User-with-dash@domain.com",
      "User+with+plus@domain.com",
      "User%with!everything&everything=@domain.somewhere"
    );

    String alias0 = "user0@tld0.com";
    String alias1 = "user1@tld1.com";

    for (String email : addresses) {
      String srs0 = srs.forward(email, alias0).toLowerCase();
      String srsRev = srs.reverse(srs0);
      assertTrue(srsRev.equalsIgnoreCase(email), String.format("%s reverses to %s case insensitively", srs0, email));

      String srs1 = srs.forward(srs0, alias1).toLowerCase();
      srsRev = srs.reverse(srs1);
      assertTrue(srsRev.equalsIgnoreCase(srs0));
    }
  }
}

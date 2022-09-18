package io.github.mschout.email.srs;

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.provider.SRSProvider;
import io.github.mschout.email.srs.provider.SRSProviderFactory;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class SRSTest {

  @Test
  void guardedSRS() throws InvalidKeyException {
    SRS srs = SRS.guardedSRS(ImmutableList.of("dummy-secret"));

    String origAddress = "jdoe@example.com";

    String forward = srs.forward(origAddress, "other.com");
    assertNotEquals(origAddress, forward);

    String reverse = srs.reverse(forward);
    assertEquals(reverse, origAddress);
  }

  @Test
  void isSRS() {
    SRS srs = SRS.guardedSRS(ImmutableList.of("dummy-secret"));

    assertTrue(srs.isSRS("SRS0=5gnp=ZU=example.com=jdoe@other.com"));
    assertFalse(srs.isSRS("jdoe@example.com"));
  }

  @Test
  public void separatorTests() throws InvalidKeyException {
    List<String> tests = ImmutableList.of(
      "user@domain-with-dash.com",
      "user-with-dash@domain.com",
      "user+with+plus@domain.com",
      "user=with=equals@domain.com",
      "user%with!everything&everything=@domain.somewhere"
    );

    for (String separator : ImmutableList.of("-", "+", "=")) {
      SRSProvider provider = SRSProviderFactory
        .builder()
        .separator(separator)
        .hashMinLength(4)
        .hashLength(4)
        .build()
        .createProvider(SRS.Type.GUARDED, ImmutableList.of("foo"));

      SRS srs = new SRS(provider);

      assertInstanceOf(SRS.class, srs, "Created an object");
      assertEquals(separator, provider.getSeparator(), "Got the expected separator");

      String source = "user@host.tld";
      List<String> aliases = IntStream
        .rangeClosed(0, 5)
        .boxed()
        .map(i -> String.format("alias%s@host%s.tld%s", i, i, i))
        .collect(Collectors.toList());

      String srs0 = srs.forward(source, aliases.get(0));
      assertTrue(srs0.startsWith("SRS0" + separator), "It uses the right initial prefix");

      String old0 = srs.reverse(srs0);
      assertFalse(old0.isEmpty(), "Reversed the address");
      assertEquals(old0, source, "The reversal was idempotent");

      String srs1 = srs.forward(srs0, aliases.get(1));
      assertFalse(srs1.isEmpty(), "Made another new address with the SRS address");
      assertTrue(srs1.startsWith("SRS1" + separator), "It uses the right initial separator too");

      String old1 = srs.reverse(srs1);
      assertFalse(old1.isEmpty(), "Reversed the address again");
      assertTrue(old1.startsWith("SRS0" + separator), "Got an SRS0 address");
      assertEquals(srs0, old1, "It is the original SRS0 address");

      String orig = srs.reverse(old1);
      assertEquals(source, orig, "Got back the original sender");

      for (String test : tests) {
        String srs0Addr = srs.forward(test, aliases.get(0));
        String oldAddr = srs.reverse(srs0Addr);
        assertEquals(test, oldAddr, "Idempotent on " + test);

        String srs1Addr = srs.forward(srs0Addr, aliases.get(1));
        String srs0Rev = srs.reverse(srs1Addr);
        assertEquals(srs0Addr, srs0Rev, "Idempotent on " + srs0Addr);
      }
    }

    assertThrows(
      IllegalArgumentException.class,
      () ->
        SRSProviderFactory
          .builder()
          .separator("!")
          .hashMinLength(4)
          .hashLength(4)
          .build()
          .createProvider(SRS.Type.GUARDED, ImmutableList.of("foo")),
      "Failed to create an object with bad separator"
    );
  }
}

package io.github.mschout.email.srs.provider;

import static org.junit.jupiter.api.Assertions.*;

import io.github.mschout.email.srs.SRS;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class ReversibleSRSProviderTest {
  private final SRS srs = new SRS(SRS.Type.REVERSIBLE, "foo");

  @Test
  public void conformance() throws InvalidKeyException { // ported from Mail::SRS tests
    assertEquals("foo", srs.getSecret());

    // Perl test makes 5 addresses but only uses first 3
    List<String> addresses = IntStream
      .rangeClosed(0, 2)
      .boxed()
      .map(i -> String.format("user%s@host%s.tld%s", i, i, i))
      .collect(Collectors.toList());

    String new0 = srs.forward(addresses.get(0), addresses.get(1));
    assertFalse(new0.isEmpty());
    assertTrue(new0.startsWith("SRS"), "It is an SRS address");
    String old0 = srs.reverse(new0);
    assertEquals(addresses.get(0), old0, "The reversal was idempotent");

    String new1 = srs.forward(new0, addresses.get(2));
    assertFalse(new1.isEmpty(), "Made another new address with the SRS address");
    assertTrue(new1.startsWith("SRS"), "It is an SRS address");
    String old1 = srs.reverse(new1);
    assertFalse(old1.isEmpty(), "Reversed teh address again");
    assertEquals(old1, new0, "The reversal was idempotent again");
  }
}

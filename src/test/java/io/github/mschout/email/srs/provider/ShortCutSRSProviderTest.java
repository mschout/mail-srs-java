package io.github.mschout.email.srs.provider;

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.SRS;
import io.github.mschout.email.srs.SRSAddress;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ShortCutSRSProviderTest {

  @Test
  public void compileAndParse() throws InvalidKeyException {
    SRSProvider shortCutProvider = DefaultSRSProviderFactory
      .getInstance()
      .createProvider(SRS.Type.SHORTCUT, ImmutableList.of("dummy-secret"));

    String compiled = shortCutProvider.compile("example.com", "jdoe");

    assertTrue(compiled.endsWith("=example.com=jdoe"));
    assertTrue(compiled.startsWith("SRS0="));

    SRSAddress parsed = shortCutProvider.parse(compiled);

    assertNotNull(parsed);
    assertEquals(parsed.getHost(), "example.com");
    assertEquals(parsed.getUser(), "jdoe");
  }

  @Test
  public void conformanceTests() throws InvalidKeyException {
    // Ported from Perl Mail::SRS tests
    SRS srs = new SRS(SRS.Type.SHORTCUT, "foo");

    assertNotNull(srs);
    assertInstanceOf(SRS.class, (srs));
    assertEquals("foo", srs.getSecret());

    String source = "user@host.tld";

    List<String> aliases = IntStream
      .rangeClosed(0, 5)
      .boxed()
      .map(i -> String.format("alias%s@host%s.tld%s", i, i, i))
      .collect(Collectors.toList());

    String new0 = srs.forward(source, aliases.get(0));
    assertFalse(new0.isEmpty(), "Made a new address");
    assertTrue(new0.startsWith("SRS"), "It is an SRS address");
    String old0 = srs.reverse(new0);
    assertFalse(old0.isEmpty(), "Reversed the SRS address");
    assertEquals(old0, source, "The reversal was idempotent");

    String new1 = srs.forward(new0, aliases.get(1));
    assertFalse(new1.isEmpty(), "Made another new address with the SRS address");
    assertTrue(new1.startsWith("SRS"), "It is an SRS address");
    String old1 = srs.reverse(new1);
    assertFalse(old1.isEmpty(), "Reversed teh address again");
    assertEquals(old1, source, "Got back the original sender");

    List<String> tests = ImmutableList.of(
      "user@domain-with-dash.com",
      "user-with-dash@domain.com",
      "user+with+plus@domain.com",
      "user%with!everything&everything=@domain.somewhere"
    );

    String alias = "alias@host.com";

    for (String test : tests) {
      String srsaddr = srs.forward(test, alias);
      String oldaddr = srs.reverse(srsaddr);
      assertEquals(oldaddr, test, "Idempotent on " + test);
    }
  }
}

package io.github.mschout.email.srs.provider;

import static org.junit.jupiter.api.Assertions.*;

import io.github.mschout.email.srs.SRS;
import io.github.mschout.email.srs.SRSAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ShortCutSRSProviderTest {
  private SRSProvider shortCutProvider;

  @BeforeEach
  public void createProvider() {
    shortCutProvider = new SRSProviderFactory().createProvider(SRS.Type.SHORTCUT, List.of("dummy-secret"));
  }

  @Test
  public void compileAndParse() throws NoSuchAlgorithmException, InvalidKeyException {
    String compiled = shortCutProvider.compile("example.com", "jdoe");

    assertTrue(compiled.endsWith("=example.com=jdoe"));
    assertTrue(compiled.startsWith("SRS0="));

    SRSAddress parsed = shortCutProvider.parse(compiled);

    assertNotNull(parsed);
    assertEquals(parsed.getHost(), "example.com");
    assertEquals(parsed.getUser(), "jdoe");
  }
}

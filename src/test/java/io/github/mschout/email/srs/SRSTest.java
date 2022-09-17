package io.github.mschout.email.srs;

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.collect.ImmutableList;
import java.security.InvalidKeyException;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

class SRSTest {
  private static final SRS srs = SRS.guardedSRS(ImmutableList.of("dummy-secret"));

  @Test
  void guardedSRS() throws InvalidKeyException {
    String origAddress = "jdoe@example.com";

    String forward = srs.forward(origAddress, "other.com");
    assertNotEquals(origAddress, forward);

    String reverse = srs.reverse(forward);
    assertEquals(reverse, origAddress);
  }

  @Test
  void isSRS() {
    assertTrue(srs.isSRS("SRS0=5gnp=ZU=example.com=jdoe@other.com"));
    assertFalse(srs.isSRS("jdoe@example.com"));
  }
}

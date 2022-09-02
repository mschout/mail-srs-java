package io.github.mschout.email.srs.provider;

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.base.Strings;
import org.junit.jupiter.api.Test;

public class SRSTimestampTest {

  @Test
  public void smoke() {
    String timestamp = SRSTimestamp.generate();

    assertFalse(Strings.isNullOrEmpty(timestamp));

    assertEquals(2, timestamp.length());
    assertFalse(SRSTimestamp.isInvalid(timestamp), "The timestamp is valid");

    long now = System.currentTimeMillis();
    long notLong = 60L * 60 * 24 * 3 * 1000;
    long ages = 60L * 60 * 24 * 50 * 1000;

    // past timsetamp not long ago should be ok
    assertFalse(SRSTimestamp.isInvalid(SRSTimestamp.generate(now - notLong)));

    // very old timestamp is not ok
    assertTrue(SRSTimestamp.isInvalid(SRSTimestamp.generate(now - ages)));

    // future timestamp fails
    assertTrue(SRSTimestamp.isInvalid(SRSTimestamp.generate(now + notLong)));

    // far future timestamp fails
    assertTrue(SRSTimestamp.isInvalid(SRSTimestamp.generate(now + ages)));
  }
}

package io.github.mschout.email.srs.provider;

import java.time.Instant;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
class SRSTimestamp {
  // Ported from reference implemenation.  Best not to change any of this unless you *really* know what you are doing
  private static final int TIMESTAMP_PRECISION = 60 * 60 * 24;
  private static final int TIMESTAMP_BASE_BITS = 5;
  private static final String TIMESTAMP_BASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  private static final int TIMESTAMP_SIZE = 2;
  private static final int TIMESTAMP_SLOTS = (1 << (TIMESTAMP_BASE_BITS << (TIMESTAMP_SIZE - 1)));
  private static final int DEFAULT_MAX_AGE = 21;

  private final String timestamp;
  private final int maxAge;

  /**
   * Returns true if the given timestmap is invalud, using default max age of the timestamp.
   * @param timestamp two char timestamp string
   * @return true if the timestamp is invalid, false otherwise
   */
  public static boolean isInvalid(String timestamp) {
    return isInvalid(timestamp, DEFAULT_MAX_AGE);
  }

  /**
   * Returns true if the timstamp is invalid.
   * @param timestamp two char timestamp string
   * @param maxAge number of seconds old that the timestamp could have been generated
   * @return true if the timestamp is invalid, false otherwise
   */
  public static boolean isInvalid(String timestamp, int maxAge) {
    return new SRSTimestamp(timestamp, maxAge).isInvalid();
  }

  /**
   * Generates a new timestamp string for the current time.
   * @return two character string representing the timestamp
   */
  public static String generate() {
    return generate(System.currentTimeMillis());
  }

  /**
   * Generates a timestamp string for the given instant in time.
   * @param nowMillis system time in milliseconds.
   * @return two character string representing the given timestamp
   */
  public static String generate(Long nowMillis) {
    long now = nowMillis / 1000;

    now = now / TIMESTAMP_PRECISION;

    char[] buf = new char[2];

    buf[1] = TIMESTAMP_BASE_CHARS.charAt((int) (now & ((1 << TIMESTAMP_BASE_BITS) - 1)));
    now = now >> TIMESTAMP_BASE_BITS;
    buf[0] = TIMESTAMP_BASE_CHARS.charAt((int) (now & ((1 << TIMESTAMP_BASE_BITS) - 1)));

    return new String(buf);
  }

  /**
   * Returns true if the timestamp string is too old to be considered valid.
   * @return true if the timestamp is too old to be valid, false otherwise.
   */
  public boolean isInvalid() {
    long then = 0L;

    for (char c : timestamp.toCharArray()) {
      int charPos = TIMESTAMP_BASE_CHARS.indexOf(Character.toUpperCase(c));

      if (charPos == -1) throw new IllegalArgumentException("Bad timestamp character: " + c);

      then = (then << TIMESTAMP_BASE_BITS) | charPos;
    }

    long now = Instant.now().toEpochMilli() / 1000;

    now = (now / TIMESTAMP_PRECISION) % TIMESTAMP_SLOTS;

    while (now < then) {
      now = now + TIMESTAMP_SLOTS;
    }

    return (now > then + maxAge);
  }
}

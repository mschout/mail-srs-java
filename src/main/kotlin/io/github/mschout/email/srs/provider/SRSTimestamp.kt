package io.github.mschout.email.srs.provider

/**
 * Utility object for generating and validating SRS (Sender Rewriting Scheme) timestamps.
 *
 * The `SRSTimestamp` class provides methods to create compact, encoded timestamps and validate
 * their age against a specified maximum age. These timestamps are used within the SRS system to
 * ensure SPF (Sender Policy Framework) compliance during email forwarding.
 *
 * The timestamp encoding compresses time information into a fixed-length string, facilitating
 * compact storage and efficient comparison of time-based data.
 *
 * This object is intended for internal use and is not designed for general purpose timestamp
 * generation or validation outside the SRS context.
 */
internal object SRSTimestamp {

  private const val TIMESTAMP_PRECISION = 60 * 60 * 24
  private const val TIMESTAMP_BASE_BITS = 5
  private const val TIMESTAMP_BASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  private const val TIMESTAMP_SIZE = 2
  private val TIMESTAMP_SLOTS = 1 shl (TIMESTAMP_BASE_BITS shl (TIMESTAMP_SIZE - 1))
  private const val DEFAULT_MAX_AGE = 21

  @JvmStatic fun generate(): String = generate(System.currentTimeMillis())

  @JvmStatic
  fun generate(nowMillis: Long): String {
    var now = nowMillis / 1000 / TIMESTAMP_PRECISION

    val buf = CharArray(2)
    buf[1] = TIMESTAMP_BASE_CHARS[(now and ((1L shl TIMESTAMP_BASE_BITS) - 1)).toInt()]
    now = now shr TIMESTAMP_BASE_BITS
    buf[0] = TIMESTAMP_BASE_CHARS[(now and ((1L shl TIMESTAMP_BASE_BITS) - 1)).toInt()]

    return String(buf)
  }

  @JvmStatic
  @JvmOverloads
  fun isInvalid(timestamp: String, maxAge: Int = DEFAULT_MAX_AGE): Boolean {
    var then = 0L

    for (c in timestamp) {
      val charPos = TIMESTAMP_BASE_CHARS.indexOf(c.uppercaseChar())
      if (charPos == -1) throw IllegalArgumentException("Bad timestamp character: $c")
      then = (then shl TIMESTAMP_BASE_BITS) or charPos.toLong()
    }

    var now = System.currentTimeMillis() / 1000
    now = (now / TIMESTAMP_PRECISION) % TIMESTAMP_SLOTS

    while (now < then) {
      now += TIMESTAMP_SLOTS
    }

    return now > then + maxAge
  }
}

package io.github.mschout.email.srs.provider

import java.security.InvalidKeyException

/**
 * A specialized implementation of [ShortCutSRSProvider] that supports reversible Sender Rewriting
 * Scheme (SRS).
 *
 * ReversibleSRSProvider is used to rewrite email sender addresses to ensure return path
 * verification and compatibility with forwarding systems. By extending [ShortCutSRSProvider], this
 * class adds enhanced support for reversible transformations where the original sender information
 * can be retrieved from the rewritten address.
 *
 * @param secrets A list of shared secrets used to generate and verify hashes.
 * @param hashLength The length of the generated hash in the output SRS address.
 * @param hashMinLength The minimum acceptable length of a valid hash for verification purposes.
 * @param separator The character used as a separator in the SRS address.
 * @constructor Initializes a new instance of ReversibleSRSProvider with the given configuration
 *   parameters.
 * @throws IllegalArgumentException If the separator is not one of the allowed characters (-, +, =).
 */
class ReversibleSRSProvider(
    secrets: List<String>,
    hashLength: Int,
    hashMinLength: Int,
    separator: String,
) : ShortCutSRSProvider(secrets, hashLength, hashMinLength, separator) {

  @Throws(InvalidKeyException::class)
  override fun compile(host: String, user: String): String {
    val timestamp = SRSTimestamp.generate()
    val hash = createHash(listOf(timestamp, host, user))
    return listOf(SRS0_PREFIX, hash, timestamp, host, user).joinToString(SRSSEP)
  }
}

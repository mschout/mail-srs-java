package io.github.mschout.email.srs.provider

import io.github.mschout.email.srs.SRSAddress
import java.security.InvalidKeyException
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Implementation of the SRSProvider interface for handling Sender Rewriting Scheme (SRS). This
 * class provides functionalities to encode and decode email addresses for forwarding while
 * maintaining SPF (Sender Policy Framework) compliance.
 *
 * @param secrets A list of secrets used for generating and validating hashes.
 * @param hashLength The length of the hash to be generated.
 * @param hashMinLength The minimum valid length of a hash.
 * @param separator A character used as a delimiter in the generated SRS address. Must be one of the
 *   valid separators: `=`, `-`, or `+`.
 * @property secret Retrieves the primary secret from the list of provided secrets.
 * @property separator The specified delimiter used within the SRS addresses.
 * @constructor Creates a ShortCutSRSProvider instance with the specified configuration.
 * @throws IllegalArgumentException If the provided separator is not a valid character.
 */
open class ShortCutSRSProvider(
    val secrets: List<String>,
    private val hashLength: Int,
    private val hashMinLength: Int,
    override val separator: String,
) : SRSProvider {

  protected val SRSSEP = "="
  protected val separators = "-+="

  init {
    require(separator in separators.map { it.toString() }) {
      "Initial separator must be = - or +, not $separator"
    }
  }

  override val secret: String
    get() = secrets[0]

  @Throws(InvalidKeyException::class)
  protected fun createHash(value: List<String>): String = createHash(value, secret)

  private fun createHash(value: List<String>, secret: String): String {
    val algorithm = "HmacSHA1"
    val secretKeySpec = SecretKeySpec(secret.toByteArray(), algorithm)
    val mac = Mac.getInstance(algorithm)
    mac.init(secretKeySpec)

    val data = value.joinToString("").lowercase()
    return Base64.getEncoder()
        .encodeToString(mac.doFinal(data.toByteArray()))
        .substring(0, hashLength)
  }

  protected fun isHashInvalid(value: List<String>, hash: String): Boolean {
    if (hash.length < hashMinLength) return false

    val validHashes = mutableListOf<String>()

    for (secret in secrets) {
      try {
        val candidate = createHash(value, secret)
        if (candidate == hash) return false
        validHashes.add(candidate)
      } catch (_: InvalidKeyException) {
        return true
      }
    }

    for (candidate in validHashes) {
      if (candidate.equals(hash, ignoreCase = true)) return false
    }

    return true
  }

  protected fun isSepChar(ch: Char): Boolean = ch in separators

  override fun isSRS0(address: String): Boolean {
    return address.uppercase().startsWith(SRS0_PREFIX) && isSepChar(address[SRS0_PREFIX.length])
  }

  override fun isSRS1(address: String): Boolean {
    return address.uppercase().startsWith(SRS1_PREFIX) && isSepChar(address[SRS1_PREFIX.length])
  }

  protected fun removePrefix(address: String): String =
      when {
        isSRS1(address) -> address.substring(SRS1_PREFIX.length + 1)
        isSRS0(address) -> address.substring(SRS0_PREFIX.length + 1)
        else -> address
      }

  @Throws(InvalidKeyException::class)
  override fun compile(host: String, user: String): String {
    var actualHost = host
    var actualUser = user
    val timestamp = SRSTimestamp.generate()

    if (isSRS0(actualUser)) {
      actualUser = removePrefix(actualUser)
      val parts = actualUser.split(SRSSEP, limit = 4)
      actualHost = parts[2]
      actualUser = parts[3]
    } else if (isSRS1(actualUser)) {
      val parts = actualUser.split(SRSSEP, limit = 6)
      actualHost = parts[3]
      actualUser = parts[4]
    }

    val hash = createHash(listOf(timestamp, actualHost, actualUser))

    return SRS0_PREFIX +
        separator +
        listOf(hash, timestamp, actualHost, actualUser).joinToString(SRSSEP)
  }

  override fun parse(srsAddress: String): SRSAddress {
    require(isSRS0(srsAddress)) { "Reverse address $srsAddress does not start with $SRS0_PREFIX=" }

    val address = removePrefix(srsAddress)

    try {
      val parts = address.split(SRSSEP, limit = 4)
      val hash = parts[0]
      val timestamp = parts[1]
      val host = parts[2]
      val user = parts[3]

      if (isHashInvalid(listOf(timestamp, host, user), hash)) {
        throw IllegalArgumentException("Invalid address hash: $hash")
      }

      if (SRSTimestamp.isInvalid(timestamp)) {
        throw IllegalArgumentException("Invalid timestamp")
      }

      return SRSAddress(SRS0_PREFIX, host, user, hash)
    } catch (e: IndexOutOfBoundsException) {
      throw IllegalArgumentException("Invalid SRS Address: $srsAddress")
    }
  }
}

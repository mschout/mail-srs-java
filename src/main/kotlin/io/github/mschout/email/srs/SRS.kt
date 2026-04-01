package io.github.mschout.email.srs

import io.github.mschout.email.srs.provider.DefaultSRSProviderFactory
import io.github.mschout.email.srs.provider.SRSProvider
import java.security.InvalidKeyException

/**
 * The SRS (Sender Rewriting Scheme) class provides functionality to rewrite the return-path in
 * emails to prevent sender address forgery and allow bounce messages to pass SPF (Sender Policy
 * Framework) checks.
 *
 * The class allows forwarding and reversing of email addresses according to the configured SRS
 * mechanism.
 *
 * @constructor Provides multiple constructors for creating an SRS instance.
 * - Can be initialized using a list of secrets and SRS type.
 * - Can also be initialized with a single secret.
 * - Allows direct injection of an SRSProvider for custom implementations.
 */
class SRS {

  enum class Type {
    GUARDED,
    REVERSIBLE,
    SHORTCUT,
  }

  private val provider: SRSProvider

  /**
   * Constructs an instance of the SRS class with the specified type and secrets.
   *
   * @param type The type of the SRS implementation to be used. Can be one of the values in the
   *   `Type` enum:
   *     - `GUARDED`: Provides added security by validating the address hash to prevent tampering.
   *     - `REVERSIBLE`: Allows reverse mapping of SRS addresses into their original unmodified
   *       form.
   *     - `SHORTCUT`: Offers a simplified SRS implementation with minimal transformations.
   *
   * @param secrets A list of secret keys used for generating and validating hashes in the SRS
   *   process. The secrets help ensure the integrity and security of the SRS addresses.
   */
  constructor(type: Type, secrets: List<String>) {
    this.provider = DefaultSRSProviderFactory.instance.createProvider(type, secrets)
  }

  /**
   * Constructs an instance of the SRS class using a single secret.
   *
   * This constructor initializes an instance of the SRS class using the provided type and secret.
   * The `secret` parameter is wrapped into a list of secrets and passed to the primary constructor.
   *
   * @param type The type of SRS to be used, defined by the enum class `Type`. Possible values:
   *   GUARDED, REVERSIBLE, SHORTCUT.
   * @param secret The shared secret used for signing and verifying addresses in the SRS system.
   */
  constructor(type: Type, secret: String) : this(type, listOf(secret))

  /**
   * Constructs an instance of the SRS class with a specified SRSProvider.
   *
   * @param provider An implementation of the SRSProvider interface that handles various operations
   *   related to the Sender Rewriting Scheme (SRS), such as compiling and parsing SRS addresses.
   */
  constructor(provider: SRSProvider) {
    this.provider = provider
  }

  /**
   * Determines whether the given email address is an SRS (Sender Rewriting Scheme) address. This
   * method checks if the address conforms to either the SRS0 or SRS1 format.
   *
   * @param address The email address to be evaluated.
   * @return `true` if the address is an SRS address; otherwise, `false`.
   */
  fun isSRS(address: String): Boolean = provider.isSRS0(address) || provider.isSRS1(address)

  /**
   * Rewrites the sender's email address for forwarding purposes while maintaining SRS (Sender
   * Rewriting Scheme) compatibility.
   *
   * @param sender The original sender's email address to be rewritten. Must contain an '@'
   *   character.
   * @param alias The alias (forwarding address) used to rewrite the sender address.
   * @param alwaysRewrite Optional flag indicating whether the email address should always be
   *   rewritten, even if the alias and sender hosts are the same. Defaults to `false`.
   * @return The rewritten email address formatted for forwarding.
   * @throws IllegalArgumentException If the sender's email address is invalid or improperly
   *   formatted.
   * @throws InvalidKeyException If an error occurs during an internal processing step, such as
   *   compiling the new address.
   */
  @JvmOverloads
  @Throws(InvalidKeyException::class)
  fun forward(sender: String, alias: String, alwaysRewrite: Boolean = false): String {
    val atPos = sender.indexOf('@')
    if (atPos == -1) throw IllegalArgumentException("Sender $sender contains no @")

    val sendUser = sender.substring(0, atPos)
    val sendHost = sender.substring(atPos + 1)

    if (sendUser.indexOf('@') != -1) {
      throw IllegalArgumentException("Sender username may not contain an @")
    }

    var aliasHost = alias
    val aliasAtPos = aliasHost.indexOf('@')
    if (aliasAtPos != -1) aliasHost = aliasHost.substring(aliasAtPos + 1)

    if (aliasHost.equals(sendHost, ignoreCase = true) && !alwaysRewrite) {
      return "$sendUser@$sendHost"
    }

    return provider.compile(sendHost, sendUser) + "@" + aliasHost
  }

  /**
   * Reverses an SRS (Sender Rewriting Scheme) address back into its original email address.
   *
   * This method identifies and extracts the user and host portion of the provided SRS address,
   * parsing it back to its original form.
   *
   * @param address The email address to reverse. Must contain an '@' character.
   * @return The original email address extracted from the SRS address.
   * @throws IllegalArgumentException If the provided address does not contain an '@' character.
   */
  fun reverse(address: String): String {
    val atPos = address.indexOf('@')
    if (atPos == -1) throw IllegalArgumentException("Address contains no @")

    val user = address.substring(0, atPos)
    val parsedAddr = provider.parse(user)

    return "${parsedAddr.user}@${parsedAddr.host}"
  }

  val secret: String
    get() = provider.secret

  companion object {
    /**
     * Creates an SRS (Sender Rewriting Scheme) instance using the GUARDED type.
     *
     * The GUARDED type ensures added security by validating the address hash to prevent tampering.
     *
     * @param secrets A list of secret keys used for generating and validating hashes in the SRS
     *   process. The secrets help ensure the integrity and security of SRS addresses.
     * @return An instance of the SRS class configured with the GUARDED type and the provided
     *   secrets.
     */
    @JvmStatic fun guardedSRS(secrets: List<String>): SRS = SRS(Type.GUARDED, secrets)
  }
}

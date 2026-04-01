/*
 * Copyright 2026 Michael Schout
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.mschout.email.srs.provider

import io.github.mschout.email.srs.SRSAddress
import java.security.InvalidKeyException

/**
 * A specialized implementation of the ShortCutSRSProvider for handling the SRS1 variations of the
 * Sender Rewriting Scheme (SRS). It adds additional parsing and compiling logic specific to
 * SRS1-formatted email addresses while leveraging the base functionality provided by the
 * ShortCutSRSProvider.
 *
 * This class is responsible for transforming and validating email addresses to ensure SPF
 * compliance during email forwarding, specifically focusing on the SRS1 logic.
 *
 * @param secrets A list of secret keys used for generating and validating hashes.
 * @param hashLength The desired length of the hash produced by this provider.
 * @param hashMinLength The minimum acceptable length of the hash for validation.
 * @param separator The separator character used for assembling SRS addresses.
 * @constructor Creates an instance of GuardedSRSProvider with the given configuration.
 */
class GuardedSRSProvider(
    secrets: List<String>,
    hashLength: Int,
    hashMinLength: Int,
    separator: String,
) : ShortCutSRSProvider(secrets, hashLength, hashMinLength, separator) {

  /**
   * Parses the provided SRS (Sender Rewriting Scheme) address into a structured SRSAddress object.
   *
   * If the address is of type SRS1, the method validates its parts (host, user, and hash) and
   * constructs an SRSAddress object. If the address is not SRS1, it delegates the parsing to the
   * superclass implementation.
   *
   * @param srsAddress The SRS address string to parse.
   * @return An SRSAddress object representing the structured details of the parsed SRS address.
   * @throws IllegalArgumentException If the SRS1 address is invalid or its components are
   *   malformed.
   */
  override fun parse(srsAddress: String): SRSAddress {
    if (isSRS1(srsAddress)) {
      val address = removePrefix(srsAddress)

      try {
        val parts = address.split(SRSSEP, limit = 3)
        val hash = parts[0]
        val host = parts[1]
        val user = parts[2]

        if (isHashInvalid(listOf(host, user), hash)) {
          throw IllegalArgumentException("Invalid SRS1 Address: $srsAddress")
        }

        if (host.isEmpty()) {
          throw IllegalArgumentException("Invalid SRS1 Address: $srsAddress")
        }

        return SRSAddress(SRS1_PREFIX, host, SRS0_PREFIX + user, hash)
      } catch (e: IndexOutOfBoundsException) {
        throw IllegalArgumentException("Invalid SRS1 Address: $srsAddress")
      }
    }

    return super.parse(srsAddress)
  }

  /**
   * Compiles an SRS (Sender Rewriting Scheme) address based on the provided host and user
   * identifiers. The method generates an SRS1 address by analyzing whether the `user` input is
   * already in SRS0 or SRS1 format, adjusting it accordingly, generating a hash, and constructing
   * the final address.
   *
   * @param host The host component of the address.
   * @param user The user portion of the address, which may already include SRS formatting.
   * @return The compiled SRS1-formatted address string.
   * @throws InvalidKeyException If the hash generation fails due to an invalid key.
   */
  @Throws(InvalidKeyException::class)
  override fun compile(host: String, user: String): String {
    if (isSRS1(user)) {
      val strippedUser = removePrefix(user)

      val parts = strippedUser.split("-", "+", "=", limit = 3)
      val srsHost = parts[1]
      val srsUser = parts[2]

      val hash = createHash(listOf(srsHost, srsUser))

      return SRS1_PREFIX + separator + listOf(hash, srsHost, srsUser).joinToString(SRSSEP)
    } else if (isSRS0(user)) {
      val strippedUser = user.substring(SRS0_PREFIX.length)

      val hash = createHash(listOf(host, strippedUser))

      return SRS1_PREFIX + separator + listOf(hash, host, strippedUser).joinToString(SRSSEP)
    }

    return super.compile(host, user)
  }
}

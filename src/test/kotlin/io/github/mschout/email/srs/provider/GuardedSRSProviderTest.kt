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

import io.github.mschout.email.srs.SRS
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldMatch
import io.kotest.matchers.string.shouldStartWith

class GuardedSRSProviderTest :
    FunSpec({
      lateinit var srs: SRS

      beforeEach { srs = SRS(SRS.Type.GUARDED, "foo") }

      test("forward") {
        val addr = "user@domain-with-dash.com"

        val srs0 = srs.forward(addr, "foo.com")
        val srs1 = srs.forward(srs0, addr)

        srs0 shouldStartWith "SRS0"
        srs1 shouldStartWith "SRS1"
        srs1[4] shouldBe '='

        srs0 shouldMatch Regex("SRS0=\\S{4}=\\S{2}=domain-with-dash\\.com=user@foo.com")
        srs1 shouldMatch
            Regex(
                "SRS1=\\S{4}=foo.com==\\S{4}=\\S{2}=domain-with-dash\\.com=user@domain-with-dash\\.com"
            )

        srs.reverse(srs0) shouldBe addr
        srs.reverse(srs1) shouldBe srs0
        srs.reverse(srs.reverse(srs1)) shouldBe addr
      }

      test("reverse") {
        val addr = "user@domain-with-dash.com"

        val alias0 = srs.forward(addr, "foo.com")
        val alias1 = srs.forward(alias0, addr)

        srs.reverse(alias1) shouldBe alias0
        srs.reverse(alias0) shouldBe addr
      }

      test("usernames") {
        val addresses =
            listOf(
                "user@domain-with-dash.com",
                "user-with-dash@domain.com",
                "user+with+plus@domain.com",
                "user%with!everything&everything=@domain.somewhere",
            )

        val aliases = listOf("user1@tld1.com", "user2@tld2.com")

        for (email in addresses) {
          val srs0 = srs.forward(email, aliases[0])
          srs.reverse(srs0) shouldBe email

          val srs1 = srs.forward(srs0, aliases[1])
          srs.reverse(srs1) shouldBe srs0

          // idempotent from same domain
          srs.forward(srs0, aliases[0]) shouldBe srs0
        }
      }

      test("invalidHash") {
        val srs0 = srs.forward("user@domain.com", "example.com")

        val invalidsrs = "SRS0=XXXX" + srs0.substring(srs0.indexOf('=', 8))

        val exception = shouldThrow<IllegalArgumentException> { srs.reverse(invalidsrs) }
        exception.message shouldContain "Invalid address hash: XXXX"
      }

      test("caseSensitivity") {
        val addresses =
            listOf(
                "User@domain-with-dash.com",
                "User-with-dash@domain.com",
                "User+with+plus@domain.com",
                "User%with!everything&everything=@domain.somewhere",
            )

        val alias0 = "user0@tld0.com"
        val alias1 = "user1@tld1.com"

        for (email in addresses) {
          val srs0 = srs.forward(email, alias0).lowercase()
          val srsRev = srs.reverse(srs0)
          srsRev.equals(email, ignoreCase = true).shouldBeTrue()

          val srs1 = srs.forward(srs0, alias1).lowercase()
          val srs1Rev = srs.reverse(srs1)
          srs1Rev.equals(srs0, ignoreCase = true).shouldBeTrue()
        }
      }
    })

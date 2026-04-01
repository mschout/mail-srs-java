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
package io.github.mschout.email.srs

import io.github.mschout.email.srs.provider.SRSProviderFactory
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf

class SRSTest :
    FunSpec({
      test("guardedSRS") {
        val srs = SRS.guardedSRS(listOf("dummy-secret"))

        val origAddress = "jdoe@example.com"

        val forward = srs.forward(origAddress, "other.com")
        forward shouldNotBe origAddress

        val reverse = srs.reverse(forward)
        reverse shouldBe origAddress
      }

      test("isSRS") {
        val srs = SRS.guardedSRS(listOf("dummy-secret"))

        srs.isSRS("SRS0=5gnp=ZU=example.com=jdoe@other.com").shouldBeTrue()
        srs.isSRS("jdoe@example.com").shouldBeFalse()
      }

      test("separatorTests") {
        val tests =
            listOf(
                "user@domain-with-dash.com",
                "user-with-dash@domain.com",
                "user+with+plus@domain.com",
                "user=with=equals@domain.com",
                "user%with!everything&everything=@domain.somewhere",
            )

        for (separator in listOf("-", "+", "=")) {
          val provider =
              SRSProviderFactory.builder()
                  .separator(separator)
                  .hashMinLength(4)
                  .hashLength(4)
                  .build()
                  .createProvider(SRS.Type.GUARDED, listOf("foo"))

          val srs = SRS(provider)

          srs.shouldBeInstanceOf<SRS>()
          provider.separator shouldBe separator

          val source = "user@host.tld"
          val aliases = (0..5).map { i -> "alias$i@host$i.tld$i" }

          val srs0 = srs.forward(source, aliases[0])
          srs0 shouldStartWith "SRS0$separator"

          val old0 = srs.reverse(srs0)
          old0.shouldNotBeEmpty()
          old0 shouldBe source

          val srs1 = srs.forward(srs0, aliases[1])
          srs1.shouldNotBeEmpty()
          srs1 shouldStartWith "SRS1$separator"

          val old1 = srs.reverse(srs1)
          old1.shouldNotBeEmpty()
          old1 shouldStartWith "SRS0$separator"
          srs0 shouldBe old1

          val orig = srs.reverse(old1)
          source shouldBe orig

          for (test in tests) {
            val srs0Addr = srs.forward(test, aliases[0])
            val oldAddr = srs.reverse(srs0Addr)
            test shouldBe oldAddr

            val srs1Addr = srs.forward(srs0Addr, aliases[1])
            val srs0Rev = srs.reverse(srs1Addr)
            srs0Addr shouldBe srs0Rev
          }
        }

        shouldThrow<IllegalArgumentException> {
          SRSProviderFactory.builder()
              .separator("!")
              .hashMinLength(4)
              .hashLength(4)
              .build()
              .createProvider(SRS.Type.GUARDED, listOf("foo"))
        }
      }

      test("varySeparator") {
        val tests =
            listOf(
                "user@domain-with-dash.com",
                "user-with-dash@domain.com",
                "user+with+plus@domain.com",
                "user=with=equals@domain.com",
                "user%with!everything&everything=@domain.somewhere",
            )

        val alias0 = "alias@host.com"
        val alias1 = "name@forwarder.com"
        val alias2 = "user@postal.com"

        for (type in listOf(SRS.Type.GUARDED, SRS.Type.REVERSIBLE, SRS.Type.SHORTCUT)) {
          val srs0 =
              SRS(
                  SRSProviderFactory.builder()
                      .separator("+")
                      .build()
                      .createProvider(type, listOf("foo"))
              )

          val srs1 =
              SRS(
                  SRSProviderFactory.builder()
                      .separator("-")
                      .build()
                      .createProvider(type, listOf("foo"))
              )

          val srs2 =
              SRS(
                  SRSProviderFactory.builder()
                      .separator("=")
                      .build()
                      .createProvider(type, listOf("foo"))
              )

          for (test in tests) {
            val srs0Addr = srs0.forward(test, alias0)
            val srs0Rev = srs0.reverse(srs0Addr)
            test shouldBe srs0Rev

            val srs1Addr = srs1.forward(srs0Addr, alias1)
            val srs1Rev = srs1.reverse(srs1Addr)

            if (type == SRS.Type.SHORTCUT) {
              test shouldBe srs1Rev
            } else {
              srs0Addr shouldBe srs1Rev
            }

            val srs2Addr = srs2.forward(srs1Addr, alias2)
            val srs2Rev = srs2.reverse(srs2Addr)

            if (type == SRS.Type.GUARDED) {
              srs0Addr shouldBe srs2Rev
            } else if (type == SRS.Type.REVERSIBLE) {
              srs1Addr shouldBe srs2Rev
            }
          }
        }
      }

      test("caselessTests") {
        for (type in listOf(SRS.Type.GUARDED, SRS.Type.REVERSIBLE, SRS.Type.SHORTCUT)) {
          val provider =
              SRSProviderFactory.builder()
                  .separator("+")
                  .build()
                  .createProvider(type, listOf("foo"))

          val srs = SRS(provider)

          val tests =
              listOf(
                  "User@domain-with-dash.com",
                  "User-with-dash@domain.com",
                  "User+with+plus@domain.com",
                  "User=with=equals@domain.com",
                  "User%with!everything&everything=@domain.somewhere",
              )

          val alias0 = "alias@host.com"
          val alias1 = "name@forwarder.com"

          for (test in tests) {
            val srs0Addr = srs.forward(test, alias0).lowercase()
            val srs0Rev = srs.reverse(srs0Addr)
            srs0Rev.equals(test, ignoreCase = true).shouldBeTrue()

            val srs1Addr = srs.forward(srs0Addr, alias1).lowercase()
            val srs1Rev = srs.reverse(srs1Addr)

            if (type == SRS.Type.SHORTCUT) {
              test.equals(srs1Rev, ignoreCase = true).shouldBeTrue()
            } else {
              srs0Addr.equals(srs1Rev, ignoreCase = true).shouldBeTrue()
            }
          }
        }
      }
    })

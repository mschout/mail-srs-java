package io.github.mschout.email.srs.provider

import io.github.mschout.email.srs.SRS
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.string.shouldStartWith

class ReversibleSRSProviderTest :
    FunSpec({
      val srs = SRS(SRS.Type.REVERSIBLE, "foo")

      test("conformance") {
        // Ported from Perl Mail::SRS tests
        srs.secret shouldBe "foo"

        val addresses = (0..2).map { i -> "user$i@host$i.tld$i" }

        val new0 = srs.forward(addresses[0], addresses[1])
        new0.shouldNotBeEmpty()
        new0 shouldStartWith "SRS"
        val old0 = srs.reverse(new0)
        old0 shouldBe addresses[0]

        val new1 = srs.forward(new0, addresses[2])
        new1.shouldNotBeEmpty()
        new1 shouldStartWith "SRS"
        val old1 = srs.reverse(new1)
        old1.shouldNotBeEmpty()
        old1 shouldBe new0
      }
    })

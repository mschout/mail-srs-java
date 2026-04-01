package io.github.mschout.email.srs.provider

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty

class SRSTimestampTest :
    FunSpec({
      test("smoke") {
        val timestamp = SRSTimestamp.generate()

        timestamp.shouldNotBeEmpty()
        timestamp.length shouldBe 2
        SRSTimestamp.isInvalid(timestamp).shouldBeFalse()

        val now = System.currentTimeMillis()
        val notLong = 60L * 60 * 24 * 3 * 1000
        val ages = 60L * 60 * 24 * 50 * 1000

        // past timestamp not long ago should be ok
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now - notLong)).shouldBeFalse()

        // very old timestamp is not ok
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now - ages)).shouldBeTrue()

        // future timestamp fails
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now + notLong)).shouldBeTrue()

        // far future timestamp fails
        SRSTimestamp.isInvalid(SRSTimestamp.generate(now + ages)).shouldBeTrue()
      }
    })

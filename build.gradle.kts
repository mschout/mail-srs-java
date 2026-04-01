plugins {
  id("mschout.all-conventions")
  id("io.freefair.lombok") version ("9.2.0")
  `java-library`
}

group = "io.github.mschout"

description = "mail-srs-java"

repositories {
  mavenLocal()
  mavenCentral()
}

dependencies {
  implementation("com.google.guava:guava:31.1-jre")
  testImplementation("org.junit.jupiter:junit-jupiter:5.9.0")
  testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.0")
}

// java {
//    toolchain {
//        languageVersion.set(JavaLanguageVersion.of(8))
//    }
//
//    withSourcesJar()
//    withJavadocJar()
// }
//
// tasks.test {
//    useJUnitPlatform()
// }

// tasks.withType<JavaCompile> {
//    options.encoding = "UTF-8"
// }

// tasks.withType<Javadoc> {
//    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
// }
// signing {
//  useGpgCmd()
//  sign publishing.publications
// }
//
// publishing {
//  publications {
//    maven(MavenPublication) {
//      groupId    = 'io.github.mschout'
//      artifactId = 'mail-srs-java'
//
//      from components.java
//
//      pom {
//        name = "${groupId}:${artifactId}"
//        description = 'Interface to Email Sender Rewriting Scheme for Java'
//        url = 'https://github.com/mschout/mail-srs-java'
//        licenses {
//          license {
//            name = 'The Apache License, Version 2.0'
//            url = 'https://www.apache.org/licenses/LICENSE-2.0.txt'
//          }
//        }
//        developers {
//          developer {
//            name = 'Michael Schout'
//            email = 'schoutm@gmail.com'
//            organizationUrl = 'https://github.com/mscnout'
//          }
//        }
//        scm {
//          connection = 'scm:git:git://github.com/mschout/mail-srs-java.git'
//          developerConnection = 'scm:git:ssh://github.com:mschout/mail-srs-java.git'
//          url = 'https://github.com/mschout/mail-srs-java/tree/master'
//        }
//      }
//    }
//  }
// }
//
// jgitver {
//  autoIncrementPatch false;
// }

// nexusPublishing {
//  repositories {
//    sonatype {
//      nexusUrl = uri("https://s01.oss.sonatype.org/service/local/")
//      snapshotRepositoryUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
//      username = System.getenv("OSSRH_USERNAME") ?: 'credentials'
//      password = System.getenv("OSSRH_PASSWORD") ?: 'credentials'
//    }
//  }
// }

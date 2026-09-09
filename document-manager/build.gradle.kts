import project.convention.logic.config.LibraryModule

plugins {
    // EUDI-changed: the app hosts this module, so it uses the app's library convention
    // plugin instead of upstream's eudi.android-library, and is not published from here.
    id("project.android.library")
    alias(libs.plugins.kotlin.serialization)
}

val NAMESPACE: String by project

moduleConfig {
    module = LibraryModule.CoreDocumentManager
}

android {
    namespace = NAMESPACE
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }
}

// EUDI-changed: opt-ins upstream's convention plugin supplies, plus the extra one
// document-manager needs.
kotlin {
    compilerOptions {
        freeCompilerArgs.addAll(
            "-opt-in=kotlin.RequiresOptIn",
            "-opt-in=kotlin.time.ExperimentalTime",
            "-opt-in=kotlin.ExperimentalApi",
        )
    }
}

dependencies {
    api(libs.multipaz) {
        exclude(group = "org.bouncycastle")
        exclude(group = "io.ktor")
    }

    implementation(libs.kotlinx.io.core)
    implementation(libs.kotlinx.io.bytestring)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)

    implementation(libs.upokecenter.cbor)
    implementation(libs.cose.java)

    api(libs.eudi.lib.jvm.sdjwt.kt)

    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.client.serialization)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.nimbus.jose.jwt)

    implementation(libs.bouncy.castle.prov)
    implementation(libs.bouncy.castle.pkix)

    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.json)
    testImplementation(libs.kotlin.coroutines.test)
    testImplementation(libs.ktor.client.cio)
}

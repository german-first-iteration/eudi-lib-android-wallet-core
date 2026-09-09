import project.convention.logic.config.LibraryModule

plugins {
    // EUDI-changed: the app hosts this module, so it uses the app's library convention
    // plugin instead of upstream's eudi.android-library, and is not published from here.
    id("project.android.library")
    id("kotlin-parcelize")
}

val NAMESPACE: String by project

moduleConfig {
    module = LibraryModule.CoreTransferManager
}

android {
    namespace = NAMESPACE
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }
}

// EUDI-changed: opt-ins upstream's convention plugin supplies.
kotlin {
    compilerOptions {
        freeCompilerArgs.addAll(
            "-opt-in=kotlin.RequiresOptIn",
            "-opt-in=kotlin.time.ExperimentalTime",
        )
    }
}

dependencies {
    // EUDI-changed: :document-manager upstream, :core:document-manager inside the app.
    implementation(project(":core:document-manager"))

    implementation(libs.appcompat)
    implementation(libs.multipaz.android) {
        exclude(group = "org.bouncycastle")
        exclude(group = "io.ktor")
    }
    implementation(libs.multipaz.android.legacy) {
        exclude(group = "org.bouncycastle")
        exclude(group = "io.ktor")
    }

    implementation(libs.kotlinx.io.core)
    implementation(libs.kotlinx.io.bytestring)

    implementation(libs.zxing.core)

    implementation(libs.bouncy.castle.prov)
    implementation(libs.bouncy.castle.pkix)

    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.json)
    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.robolectric)
    testImplementation(libs.upokecenter.cbor)
    testImplementation(libs.cose.java)

    androidTestImplementation(libs.android.junit)
    androidTestImplementation(libs.espresso.core)
}

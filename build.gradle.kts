plugins {
    kotlin("jvm") version "2.3.20"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core-jvm:3.5.1")
    implementation("io.ktor:ktor-server-netty-jvm:3.5.1")
    implementation("org.xerial:sqlite-jdbc:3.46.1.3")
    implementation("ch.qos.logback:logback-classic:1.5.37")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    mainClass.set("prism.MainKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}

dependencyLocking {
    lockAllConfigurations()
}

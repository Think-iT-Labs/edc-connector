/*
 *  Copyright (c) 2022 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *
 */


plugins {
    `java-library`
    alias(libs.plugins.edc.build)
}

val edcScmUrl: String by project
val edcScmConnection: String by project

buildscript {
    repositories {
        mavenCentral()
        maven {
            url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
        }
    }
    dependencies {
        classpath("org.eclipse.edc.autodoc:org.eclipse.edc.autodoc.gradle.plugin:0.15.1")
    }
}

val edcBuildId = libs.plugins.edc.build.get().pluginId

allprojects {
    apply(plugin = edcBuildId)
    // Temporarily disable autodoc plugin due to version mismatch
    // apply(plugin = "org.eclipse.edc.autodoc")

    configure<org.eclipse.edc.plugins.edcbuild.extensions.BuildExtension> {
        pom {
            scmUrl.set(edcScmUrl)
            scmConnection.set(edcScmConnection)
        }
    }

    configure<CheckstyleExtension> {
        configFile = rootProject.file("resources/edc-checkstyle-config.xml")
        configDirectory.set(rootProject.file("resources"))
    }

    afterEvaluate {
        repositories.clear()
        repositories {
            mavenCentral()
            maven {
                url = uri("https://oss.sonatype.org/content/repositories/snapshots/")
            }
        }
    }

}

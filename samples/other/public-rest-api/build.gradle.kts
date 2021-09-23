/*
 *  Copyright (c) 2020, 2021 Microsoft Corporation
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
}

val rsApi: String by project

dependencies {
    api(project(":spi"))
    implementation(project(":common:util"))
    implementation(project(":extensions:in-memory:metadata-memory"))
    implementation(project(":core:protocol:web"))

    implementation(project(":extensions:catalog:catalog-service"))
    implementation("jakarta.ws.rs:jakarta.ws.rs-api:${rsApi}")

}

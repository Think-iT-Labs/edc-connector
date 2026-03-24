/*
 *  Copyright (c) 2026 Think-it GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Think-it GmbH - initial API and implementation
 *
 */

package org.eclipse.edc.web.spi.configuration.context;

import org.eclipse.edc.runtime.metamodel.annotation.Setting;
import org.eclipse.edc.runtime.metamodel.annotation.Settings;
import org.eclipse.edc.spi.EdcException;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.web.spi.configuration.ApiContext;
import org.eclipse.edc.web.spi.configuration.PortMapping;

import java.net.URI;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;

@Settings
public record ControlApiConfiguration(
        @Setting(
                key = "web.http." + ApiContext.CONTROL + ".port",
                description = "Port for " + ApiContext.CONTROL + " api context",
                defaultValue = DEFAULT_CONTROL_PORT + "")
        int port,

        @Setting(
                key = "web.http." + ApiContext.CONTROL + ".path",
                description = "Path for " + ApiContext.CONTROL + " api context",
                defaultValue = DEFAULT_CONTROL_PATH)
        String path,

        @Setting(
                key = "web.http." + ApiContext.CONTROL + ".public.uri",
                description = "Public uri for " + ApiContext.CONTROL + " api context. If not defined, the 'localhost' one will be used.",
                required = false)
        String publicUri,

        @Deprecated(since = "0.17.0")
        @Setting(
                key = "edc.control.endpoint",
                description = "Configures endpoint for reaching the Control API. If it's missing it defaults to the hostname configuration.",
                required = false)
        String controlEndpoint
) {

    public static final int DEFAULT_CONTROL_PORT = 9191;
    public static final String DEFAULT_CONTROL_PATH = "/api/control";

    @Override
    public String publicUri() {
        forcePublicUriConfiguration();
        var callbackAddress = ofNullable(publicUri).orElseGet(() -> format("http://localhost:%s%s", port(), path()));

        try {
            return callbackAddress;
        } catch (IllegalArgumentException e) {
            throw new EdcException("Error creating control endpoint url", e);
        }
    }

    @Deprecated(since = "0.17.0")
    private void forcePublicUriConfiguration() {
        if (controlEndpoint != null && !controlEndpoint.isBlank()) {
            throw new EdcException("Setting 'edc.control.endpoint' has been superseded by 'web.http.control.public.uri', please update your configuration accordingly.");
        }
    }
}

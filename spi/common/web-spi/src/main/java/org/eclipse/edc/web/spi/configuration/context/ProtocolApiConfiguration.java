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
import org.eclipse.edc.web.spi.configuration.ApiContext;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;

@Settings
public record ProtocolApiConfiguration(
        @Setting(
                key = "web.http." + ApiContext.PROTOCOL + ".port",
                description = "Port for " + ApiContext.PROTOCOL + " api context",
                defaultValue = DEFAULT_PROTOCOL_PORT + "")
        int port,

        @Setting(
                key = "web.http." + ApiContext.PROTOCOL + ".path",
                description = "Path for " + ApiContext.PROTOCOL + " api context",
                defaultValue = DEFAULT_PROTOCOL_PATH)
        String path,

        @Setting(
                key = "web.http." + ApiContext.PROTOCOL + ".public.uri",
                description = "Public uri for " + ApiContext.PROTOCOL + " api context. If not defined, the 'localhost' one will be used.",
                required = false)
        String publicUri,

        @Deprecated(since = "0.17.0")
        @Setting(
                key = "edc.dsp.callback.address",
                description = "Configures endpoint for reaching the Protocol API in the form \"<hostname:protocol.port/protocol.path>\"",
                required = false)
        String callbackAddress

) {

    public static final String DEFAULT_PROTOCOL_PATH = "/api/protocol";
    public static final int DEFAULT_PROTOCOL_PORT = 8282;

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
        if (callbackAddress != null && !callbackAddress.isBlank()) {
            throw new EdcException("Setting 'edc.dsp.callback.address' has been superseded by 'web.http.protocol.public.uri', please update your configuration accordingly.");
        }
    }
}

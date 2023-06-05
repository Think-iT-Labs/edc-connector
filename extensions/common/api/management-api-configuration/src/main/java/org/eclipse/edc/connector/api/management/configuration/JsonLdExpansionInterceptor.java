/*
 *  Copyright (c) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - initial API and implementation
 *
 */

package org.eclipse.edc.connector.api.management.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.json.JsonObject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.ext.ReaderInterceptor;
import jakarta.ws.rs.ext.ReaderInterceptorContext;
import org.eclipse.edc.jsonld.spi.JsonLd;
import org.eclipse.edc.transform.spi.TypeTransformerRegistry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Provider
public class JsonLdExpansionInterceptor implements ReaderInterceptor {

    private final ObjectMapper mapper;
    private final JsonLd jsonLd;
    private final TypeTransformerRegistry transformerRegistry;

    public JsonLdExpansionInterceptor(ObjectMapper mapper, JsonLd jsonLd, TypeTransformerRegistry transformerRegistry) {
        this.mapper = mapper;
        this.jsonLd = jsonLd;
        this.transformerRegistry = transformerRegistry;
    }

    @Override
    public Object aroundReadFrom(ReaderInterceptorContext context)
            throws IOException, WebApplicationException {
        if (context.getType().equals(JsonObject.class)) {
            return context.proceed();
        }

        var is = context.getInputStream();
        var jsonObject = mapper.readValue(is, JsonObject.class);
        var content = jsonLd.expand(jsonObject).getContent();

        var dto = transformerRegistry.transform(content, context.getType()).getContent();

        var byteArrayOutputStream = new ByteArrayOutputStream();
        mapper.writeValue(byteArrayOutputStream, dto);

        context.setInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));

        return context.proceed();
    }
}

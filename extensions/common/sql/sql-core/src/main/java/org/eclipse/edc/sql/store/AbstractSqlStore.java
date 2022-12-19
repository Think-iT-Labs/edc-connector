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

package org.eclipse.edc.sql.store;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.spi.persistence.EdcPersistenceException;
import org.eclipse.edc.transaction.datasource.spi.DataSourceRegistry;
import org.eclipse.edc.transaction.spi.TransactionContext;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Objects;
import javax.sql.DataSource;

import static java.lang.String.format;

public abstract class AbstractSqlStore {
    protected final TransactionContext transactionContext;
    private final DataSourceRegistry dataSourceRegistry;
    private final String dataSourceName;

    private final ObjectMapper objectMapper;


    public AbstractSqlStore(DataSourceRegistry dataSourceRegistry, String dataSourceName, TransactionContext transactionContext, ObjectMapper objectMapper) {
        this.dataSourceRegistry = Objects.requireNonNull(dataSourceRegistry);
        this.dataSourceName = Objects.requireNonNull(dataSourceName);
        this.transactionContext = Objects.requireNonNull(transactionContext);
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    protected Connection getConnection() {
        try {
            return getDataSource().getConnection();
        } catch (SQLException e) {
            throw new EdcPersistenceException("Cannot get SQL connection", e);
        }
    }

    protected String toJson(Object object) {
        if (object == null) {
            return null;
        }
        try {
            return object instanceof String ? object.toString() : objectMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new EdcPersistenceException(e);
        }
    }

    protected <T> String toJson(Object object, TypeReference<T> typeReference) {
        if (object == null) {
            return null;
        }
        try {
            return object instanceof String ? object.toString() : objectMapper.writerFor(typeReference).writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new EdcPersistenceException(e);
        }
    }

    protected <T> T fromJson(String json, TypeReference<T> typeReference) {
        if (json == null) {
            return null;
        }
        try {
            return objectMapper.readValue(json, typeReference);
        } catch (JsonProcessingException e) {
            throw new EdcPersistenceException(e);
        }
    }

    protected <T> T fromJson(String json, Class<T> type) {

        if (json == null) {
            return null;
        }

        try {
            return objectMapper.readValue(json, type);
        } catch (JsonProcessingException e) {
            throw new EdcPersistenceException(e);
        }
    }

    private DataSource getDataSource() {
        return Objects.requireNonNull(dataSourceRegistry.resolve(dataSourceName), format("DataSource %s could not be resolved", dataSourceName));
    }
}

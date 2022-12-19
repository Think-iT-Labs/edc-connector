/*
 *  Copyright (c) 2022 Daimler TSS GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Daimler TSS GmbH - Initial API and Implementation
 *       Microsoft Corporation - added full QuerySpec support
 *
 */

package org.eclipse.edc.connector.store.sql.assetindex;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.connector.store.sql.assetindex.schema.AssetStatements;
import org.eclipse.edc.spi.asset.AssetIndex;
import org.eclipse.edc.spi.asset.AssetSelectorExpression;
import org.eclipse.edc.spi.query.Criterion;
import org.eclipse.edc.spi.query.QuerySpec;
import org.eclipse.edc.spi.types.domain.DataAddress;
import org.eclipse.edc.spi.types.domain.asset.Asset;
import org.eclipse.edc.spi.types.domain.asset.AssetEntry;
import org.eclipse.edc.sql.store.AbstractSqlStore;
import org.eclipse.edc.transaction.datasource.spi.DataSourceRegistry;
import org.eclipse.edc.transaction.spi.TransactionContext;
import org.jetbrains.annotations.Nullable;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toMap;
import static org.eclipse.edc.sql.SqlQueryExecutor.executeQuery;
import static org.eclipse.edc.sql.SqlQueryExecutor.executeQuerySingle;

public class SqlAssetIndex extends AbstractSqlStore implements AssetIndex {

    private final AssetStatements assetStatements;

    public SqlAssetIndex(DataSourceRegistry dataSourceRegistry, String dataSourceName, TransactionContext transactionContext, ObjectMapper objectMapper, AssetStatements assetStatements) {
        super(dataSourceRegistry, dataSourceName, transactionContext, objectMapper);
        this.assetStatements = Objects.requireNonNull(assetStatements);
    }

    @Override
    public Stream<Asset> queryAssets(AssetSelectorExpression expression) {
        Objects.requireNonNull(expression);

        var criteria = expression.getCriteria();
        var querySpec = QuerySpec.Builder.newInstance().filter(criteria)
                .offset(0)
                .limit(Integer.MAX_VALUE) // means effectively no limit
                .build();
        return queryAssets(querySpec);
    }

    @Override
    public Stream<Asset> queryAssets(QuerySpec querySpec) {
        Objects.requireNonNull(querySpec);

        return transactionContext.execute(() -> {
            var statement = assetStatements.createQuery(querySpec);

            return executeQuery(transactionContext, getConnection(), this::mapAssetIds, statement.getQueryAsString(), statement.getParameters())
                    .map(this::findById);
        });
    }

    @Override
    public @Nullable Asset findById(String assetId) {
        Objects.requireNonNull(assetId);

        return transactionContext.execute(() -> {
            var connection = getConnection();

            if (!existsById(transactionContext, assetId, connection)) {
                return null;
            }

            var selectAssetByIdSql = assetStatements.getSelectAssetByIdTemplate();
            var findPropertyByIdSql = assetStatements.getFindPropertyByIdTemplate();

            var createdAt = executeQuery(transactionContext, connection, this::mapCreatedAt, selectAssetByIdSql, assetId)
                    .findFirst().orElse(0L);

            var assetProperties = executeQuery(transactionContext, connection, this::mapPropertyResultSet, findPropertyByIdSql, assetId)
                    .collect(toMap(Map.Entry::getKey, Map.Entry::getValue));

            return Asset.Builder.newInstance()
                    .id(assetId)
                    .properties(assetProperties)
                    .createdAt(createdAt)
                    .build();
        });
    }

    @Override
    public void accept(AssetEntry item) {
        Objects.requireNonNull(item);
        var asset = item.getAsset();
        var dataAddress = item.getDataAddress();

        Objects.requireNonNull(asset);
        Objects.requireNonNull(dataAddress);

        var assetId = asset.getId();
        transactionContext.execute(() -> {
            var connection = getConnection();
            if (existsById(transactionContext, assetId, connection)) {
                deleteById(assetId);
            }

            executeQuery(connection, assetStatements.getInsertAssetTemplate(), assetId, asset.getCreatedAt());
            var insertDataAddressTemplate = assetStatements.getInsertDataAddressTemplate();
            executeQuery(connection, insertDataAddressTemplate, assetId, toJson(dataAddress.getProperties()));

            for (var property : asset.getProperties().entrySet()) {
                executeQuery(connection, assetStatements.getInsertPropertyTemplate(),
                        assetId,
                        property.getKey(),
                        toJson(property.getValue()),
                        property.getValue().getClass().getName());
            }
        });
    }

    @Override
    public Asset deleteById(String assetId) {
        Objects.requireNonNull(assetId);

        return transactionContext.execute(() -> {
            var asset = findById(assetId);
            if (asset == null) {
                return null;
            }

            executeQuery(getConnection(), assetStatements.getDeleteAssetByIdTemplate(), assetId);

            return asset;
        });
    }

    @Override
    public long countAssets(List<Criterion> criteria) {
        return transactionContext.execute(() -> {
            var statement = assetStatements.createQuery(criteria);
            var queryAsString = statement.getQueryAsString().replace("SELECT * ", "SELECT COUNT (*) ");
            return executeQuerySingle(transactionContext, getConnection(), r -> r.getLong(1), queryAsString, statement.getParameters());
        });
    }

    @Override
    public DataAddress resolveForAsset(String assetId) {
        Objects.requireNonNull(assetId);

        return transactionContext.execute(() -> {
            var sql = assetStatements.getFindDataAddressByIdTemplate();
            return executeQuerySingle(transactionContext, getConnection(), this::mapDataAddress, sql, assetId);
        });
    }

    private long mapCreatedAt(ResultSet resultSet) throws SQLException {
        return resultSet.getLong(assetStatements.getCreatedAtColumn());
    }

    private int mapRowCount(ResultSet resultSet) throws SQLException {
        return resultSet.getInt(assetStatements.getCountVariableName());
    }

    private Map.Entry<String, Object> mapPropertyResultSet(ResultSet resultSet) throws SQLException, ClassNotFoundException {
        var name = resultSet.getString(assetStatements.getAssetPropertyColumnName());
        var value = resultSet.getString(assetStatements.getAssetPropertyColumnValue());
        var type = resultSet.getString(assetStatements.getAssetPropertyColumnType());


        return Map.entry(name, fromPropertyValue(value, type));
    }

    /**
     * Deserializes a value into an object using the object mapper. Note: if type is {@code java.lang.String} simply
     * {@code value.toString()} is returned.
     */
    private Object fromPropertyValue(String value, String type) throws ClassNotFoundException {
        var clazz = Class.forName(type);
        if (clazz == String.class) {
            return value;
        }
        return fromJson(value, clazz);
    }

    private boolean existsById(TransactionContext transactionContext, String assetId, Connection connection) {
        var sql = assetStatements.getCountAssetByIdClause();
        return executeQuery(transactionContext, connection, this::mapRowCount, sql, assetId)
                .findFirst().orElse(0) > 0;
    }

    private DataAddress mapDataAddress(ResultSet resultSet) throws SQLException {
        return DataAddress.Builder.newInstance()
                .properties(fromJson(resultSet.getString(assetStatements.getDataAddressColumnProperties()), new TypeReference<>() {
                }))
                .build();
    }

    private String mapAssetIds(ResultSet resultSet) throws SQLException {
        return resultSet.getString(assetStatements.getAssetIdColumn());
    }

}

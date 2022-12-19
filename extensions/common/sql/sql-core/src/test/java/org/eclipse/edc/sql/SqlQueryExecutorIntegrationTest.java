/*
 *  Copyright (c) 2021 - 2022 Daimler TSS GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Daimler TSS GmbH - Initial Test
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - improvements
 *
 */

package org.eclipse.edc.sql;

import org.eclipse.edc.spi.persistence.EdcPersistenceException;
import org.eclipse.edc.transaction.spi.NoopTransactionContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SqlQueryExecutorIntegrationTest {

    private Connection connection;
    private final NoopTransactionContext context = new NoopTransactionContext();

    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection("jdbc:h2:mem:test", new Properties());
    }

    @AfterEach
    void tearDown() throws SQLException {
        if (!connection.isClosed()) {
            connection.rollback();
            connection.close();
        }
    }

    @Test
    void executeQuery() {
        ResultSetMapper<Long> mapper = (rs) -> rs.getLong(1);
        var sql = "SELECT 1;";

        context.execute(() -> {
            var result = SqlQueryExecutor.executeQuery(context, connection, mapper, sql);
            assertThat(result).isNotNull().hasSize(1).contains(1L);
        });
    }

    @Test
    void executeQuerySingle() {
        context.execute(() -> {
            SqlQueryExecutor.executeQuery(connection, "CREATE TABLE test (data VARCHAR(80) primary key not null);");
            SqlQueryExecutor.executeQuery(connection, "INSERT INTO test values ('value');");
            var sql = "SELECT data FROM test WHERE data = ?";
            ResultSetMapper<String> mapper = rs -> rs.getString(1);

            var found = SqlQueryExecutor.executeQuerySingle(context, connection, mapper, sql, "value");
            assertThat(found).isEqualTo("value");

            var notFound = SqlQueryExecutor.executeQuerySingle(context, connection, mapper, sql, "any other");
            assertThat(notFound).isEqualTo(null);
        });
    }

    @Test
    void testTransactionAndResultSetMapper() {
        context.execute(() -> {
            var table = "kv_testTransactionAndResultSetMapper";
            var kv = new Kv(UUID.randomUUID().toString(), UUID.randomUUID().toString());

            SqlQueryExecutor.executeQuery(connection, getTableSchema(table));
            SqlQueryExecutor.executeQuery(connection, format("INSERT INTO %s (k, v) values (?, ?)", table), kv.key, kv.value);

            var countResult = SqlQueryExecutor.executeQuery(context, connection, (rs) -> rs.getInt(1), format("SELECT COUNT(*) FROM %s", table));
            assertThat(countResult).hasSize(1).first().isEqualTo(1);

            var kvs = SqlQueryExecutor.executeQuery(context, connection, (rs) -> new Kv(rs.getString(1), rs.getString(2)), format("SELECT * FROM %s", table));
            assertThat(kvs).hasSize(1).first().isEqualTo(kv);
        });
    }

    @Test
    void testInvalidSql() {
        context.execute(() -> {
            assertThatThrownBy(() -> SqlQueryExecutor.executeQuery(connection, "Lorem ipsum dolor sit amet")).isInstanceOf(EdcPersistenceException.class);
        });
    }

    private String getTableSchema(String tableName) {
        return format("" +
                "CREATE TABLE %s (\n" +
                "    k VARCHAR(80) PRIMARY KEY NOT NULL,\n" +
                "    v VARCHAR(80) NOT NULL\n" +
                ");", Objects.requireNonNull(tableName));
    }

    private static class Kv {
        final String key;
        final String value;

        Kv(String key, String value) {
            this.key = key;
            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Kv kv = (Kv) o;
            return key.equals(kv.key) && Objects.equals(value, kv.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(key, value);
        }
    }
}

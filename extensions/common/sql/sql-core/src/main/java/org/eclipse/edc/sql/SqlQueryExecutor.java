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
 *       Daimler TSS GmbH - Initial API and Implementation
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - improvements
 *
 */

package org.eclipse.edc.sql;

import org.eclipse.edc.spi.persistence.EdcPersistenceException;
import org.eclipse.edc.transaction.spi.TransactionContext;
import org.jetbrains.annotations.NotNull;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static java.util.stream.StreamSupport.stream;

/**
 * The SqlQueryExecutor is capable of executing parametrized SQL queries
 */
public final class SqlQueryExecutor {

    private SqlQueryExecutor() {
    }

    /**
     * Intended for mutating queries.
     *
     * @param sql the parametrized sql query
     * @param arguments the parameters to interpolate with the parametrized sql query
     * @return rowsChanged
     */
    public static int executeQuery(Connection connection, String sql, Object... arguments) {
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(sql, "sql");
        Objects.requireNonNull(arguments, "arguments");

        try (var statement = connection.prepareStatement(sql, PreparedStatement.RETURN_GENERATED_KEYS)) {
            setArguments(statement, arguments);
            return statement.execute() ? 0 : statement.getUpdateCount();
        } catch (Exception exception) {
            throw new EdcPersistenceException(exception.getMessage(), exception);
        }
    }

    /**
     * Query and get single item.
     *
     * @param context the transactional context
     * @param connection the connection to be used to execute the query.
     * @param resultSetMapper able to map a row to an object e.g. pojo.
     * @param sql the parametrized sql query
     * @param arguments the parameters to interpolate with the parametrized sql query
     * @param <T> generic type returned after mapping from the executed query
     * @return a Stream on the results, must be collected into a transactional context block.
     */
    public static <T> T executeQuerySingle(TransactionContext context, Connection connection, ResultSetMapper<T> resultSetMapper, String sql, Object... arguments) {
        try (var stream = executeQuery(context, connection, resultSetMapper, sql, arguments)) {
            return stream.findFirst().orElse(null);
        }
    }

    /**
     * Intended for reading queries.
     * The resulting {@link Stream} must be collected inside a {@link TransactionContext} block, because the connection
     * and the related resources (statement, resultSet) are closed when the block terminates.
     *
     * @param context the transactional context.
     * @param connection the connection to be used to execute the query.
     * @param resultSetMapper able to map a row to an object e.g. pojo.
     * @param sql the parametrized sql query
     * @param arguments the parameters to interpolate with the parametrized sql query
     * @param <T> generic type returned after mapping from the executed query
     * @return a Stream on the results, must be collected into a transactional context block.
     */
    public static <T> Stream<T> executeQuery(TransactionContext context, Connection connection, ResultSetMapper<T> resultSetMapper, String sql, Object... arguments) {
        Objects.requireNonNull(context, "transactionContext");
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(resultSetMapper, "resultSetMapper");
        Objects.requireNonNull(sql, "sql");
        Objects.requireNonNull(arguments, "arguments");

        try {
            var statement = connection.prepareStatement(sql);
            context.registerSynchronization(() -> close(statement));
            statement.setFetchSize(5000);
            setArguments(statement, arguments);

            var resultSet = statement.executeQuery();
            context.registerSynchronization(() -> close(resultSet));

            var splititerator = createSpliterator(resultSetMapper, resultSet);
            return stream(splititerator, false);
        } catch (SQLException sqlEx) {
            throw new EdcPersistenceException(sqlEx);
        }
    }

    private static void close(PreparedStatement statement) {
        try {
            statement.close();
        } catch (SQLException exception) {
            throw new EdcPersistenceException("Error while closing PreparedStatement", exception);
        }
    }

    private static void close(ResultSet resultSet) {
        try {
            resultSet.close();
        } catch (SQLException exception) {
            throw new EdcPersistenceException("Error while closing ResultSet", exception);
        }
    }

    @NotNull
    private static <T> Spliterators.AbstractSpliterator<T> createSpliterator(ResultSetMapper<T> resultSetMapper, ResultSet resultSet) {
        return new Spliterators.AbstractSpliterator<>(Long.MAX_VALUE, Spliterator.ORDERED) {
            @Override
            public boolean tryAdvance(Consumer<? super T> action) {
                try {
                    if (!resultSet.next()) {
                        return false;
                    }
                    action.accept(resultSetMapper.mapResultSet(resultSet));
                    return true;
                } catch (Exception ex) {
                    throw new EdcPersistenceException(ex);
                }
            }

        };
    }

    private static void setArguments(PreparedStatement statement, Object[] arguments) throws SQLException {
        for (int index = 0; index < arguments.length; index++) {
            int position = index + 1;
            setArgument(statement, position, arguments[index]);
        }
    }

    private static void setArgument(PreparedStatement statement, int position, Object argument) throws SQLException {
        var argumentHandler = Arrays.stream(ArgumentHandlers.values()).filter(it -> it.accepts(argument))
                .findFirst().orElse(null);

        if (argumentHandler != null) {
            argumentHandler.handle(statement, position, argument);
        } else {
            statement.setObject(position, argument);
        }
    }

}

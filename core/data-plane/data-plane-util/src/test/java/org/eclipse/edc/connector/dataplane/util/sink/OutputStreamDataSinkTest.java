/*
 *  Copyright (c) 2021 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - improvements
 *
 */

package org.eclipse.edc.connector.dataplane.util.sink;

import org.eclipse.edc.connector.dataplane.spi.pipeline.DataSource;
import org.eclipse.edc.connector.dataplane.spi.pipeline.InputStreamDataSource;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.response.StatusResult;
import org.eclipse.edc.spi.result.AbstractResult;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OutputStreamDataSinkTest {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Monitor monitor = mock(Monitor.class);

    @Test
    void verifySend() {
        var data = "bar".getBytes();
        var dataSource = new InputStreamDataSource("foo", new ByteArrayInputStream(data));
        var stream = new ByteArrayOutputStream();
        var dataSink = new OutputStreamDataSink(stream, executor, monitor);

        var future = dataSink.transfer(dataSource);

        assertThat(future).succeedsWithin(10, SECONDS).matches(AbstractResult::succeeded);
        assertThat(stream.toByteArray()).isEqualTo(data);
    }

    @Test
    void shouldReturnFatalErrorOnException() {
        var dataSource = mock(DataSource.class);
        when(dataSource.openPartStream()).thenThrow(new RuntimeException("unexpected failure"));
        var dataSink = new OutputStreamDataSink(new ByteArrayOutputStream(), executor, monitor);

        var future = dataSink.transfer(dataSource);

        assertThat(future).succeedsWithin(10, SECONDS).matches(StatusResult::fatalError);
    }

    @Test
    void shouldReturnFatalErrorOnTransferError() throws IOException {
        var sourceStream = mock(InputStream.class);
        when(sourceStream.transferTo(any())).thenThrow(new RuntimeException("Error transferring data"));
        var dataSource = new InputStreamDataSource("foo", sourceStream);
        var dataSink = new OutputStreamDataSink(new ByteArrayOutputStream(), executor, monitor);

        var future = dataSink.transfer(dataSource);

        assertThat(future).succeedsWithin(10, SECONDS).matches(StatusResult::fatalError);
    }
}

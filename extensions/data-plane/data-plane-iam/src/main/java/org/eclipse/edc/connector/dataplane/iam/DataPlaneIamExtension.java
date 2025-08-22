/*
 *  Copyright (c) 2024 Contributors to the Eclipse Foundation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Contributors to the Eclipse Foundation - initial API and implementation
 *
 */

package org.eclipse.edc.connector.dataplane.iam;

import org.eclipse.edc.connector.dataplane.iam.service.DataPlaneAuthorizationServiceImpl;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessControlService;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAccessTokenService;
import org.eclipse.edc.connector.dataplane.spi.iam.DataPlaneAuthorizationService;
import org.eclipse.edc.connector.dataplane.spi.iam.PublicEndpointGeneratorService;
import org.eclipse.edc.connector.dataplane.spi.provision.ProvisionerManager;
import org.eclipse.edc.connector.dataplane.spi.provision.ResourceDefinitionGeneratorManager;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Provider;
import org.eclipse.edc.spi.security.Vault;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.spi.types.TypeManager;

import java.time.Clock;

import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIamDeprovisioner.frontChannelDeprovisioner;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIamDeprovisioner.responseChannelDeprovisioner;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIamProvisioner.frontChannelProvisioner;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIamProvisioner.responseChannelProvisioner;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIamResourceGenerator.frontChannelResourceGenerator;
import static org.eclipse.edc.connector.dataplane.iam.provision.DataPlaneIamResourceGenerator.responseChannelResourceGenerator;

@Extension(value = DataPlaneIamExtension.NAME)
public class DataPlaneIamExtension implements ServiceExtension {

    public static final String NAME = "Data Plane IAM";

    @Inject
    private Clock clock;
    @Inject
    private DataPlaneAccessTokenService accessTokenService;
    @Inject
    private DataPlaneAccessControlService accessControlService;
    @Inject
    private PublicEndpointGeneratorService endpointGenerator;
    @Inject
    private ResourceDefinitionGeneratorManager resourceDefinitionGeneratorManager;
    @Inject
    private ProvisionerManager provisionerManager;
    @Inject
    private Vault vault;
    @Inject
    private TypeManager typeManager;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        resourceDefinitionGeneratorManager.registerProviderGenerator(frontChannelResourceGenerator());
        resourceDefinitionGeneratorManager.registerProviderGenerator(responseChannelResourceGenerator());

        provisionerManager.register(frontChannelProvisioner(context.getParticipantId(), accessTokenService, vault, clock, typeManager.getMapper()));
        provisionerManager.register(responseChannelProvisioner(context.getParticipantId(), accessTokenService, vault, clock, typeManager.getMapper()));

        provisionerManager.register(frontChannelDeprovisioner(accessTokenService, vault));
        provisionerManager.register(responseChannelDeprovisioner(accessTokenService, vault));
    }

    @Provider
    public DataPlaneAuthorizationService authorizationService(ServiceExtensionContext context) {
        return new DataPlaneAuthorizationServiceImpl(accessTokenService, endpointGenerator, accessControlService,
                context.getParticipantId(), clock, vault, typeManager.getMapper());
    }
}

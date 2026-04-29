#pragma once

#include "oatpp-swagger/Model.hpp"
#include "oatpp-swagger/Resources.hpp"
#include "oatpp/core/macro/component.hpp"

/// Registers oatpp-swagger DI components:
///   - DocumentInfo  (title, version, contact, security schemes)
///   - Resources     (Swagger UI static files, path from CMake)
class SwaggerComponent {
public:
    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::swagger::DocumentInfo>,
                           swaggerDocumentInfo)([] {
        oatpp::swagger::DocumentInfo::Builder builder;
        builder
            .setTitle("Honeypot Orchestrator API")
            .setDescription(
                "Central REST API for the worldwide honeypot network. "
                "Collect events from honeybots, classify attackers (bot/human), "
                "and query statistics.\n\n"
                "**Authentication:** All endpoints except `POST /api/v1/nodes/register` "
                "require a `Bearer` JWT token in the `Authorization` header. "
                "Obtain the token by registering a node.")
            .setVersion("1.0.0")
            .setContactName("EMCL Research Group")
            .addServer("http://localhost:8080", "Local development");
            // .addSecurityScheme("BearerAuth",
            //     oatpp::swagger::DocumentInfo::SecuritySchemeBuilder
            //         ::DefaultBearerAuthorizationSecurityScheme("JWT"));
        return builder.build();
    }());

    OATPP_CREATE_COMPONENT(std::shared_ptr<oatpp::swagger::Resources>,
                           swaggerResources)([] {
        // OATPP_SWAGGER_RES_PATH is injected by CMakeLists.txt via compile definition
        return oatpp::swagger::Resources::loadResources(OATPP_SWAGGER_RES_PATH);
    }());
};

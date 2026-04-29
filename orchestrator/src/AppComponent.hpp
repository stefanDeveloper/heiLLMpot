#pragma once

#include "ConfigComponent.hpp"
#include "oatpp/core/macro/component.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"
#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/web/server/HttpRouter.hpp"

class AppComponent {
public:
    OATPP_CREATE_COMPONENT(
        std::shared_ptr<oatpp::data::mapping::ObjectMapper>, apiObjectMapper)([] {
        auto mapper = oatpp::parser::json::mapping::ObjectMapper::createShared();
        mapper->getSerializer()->getConfig()->useBeautifier   = false;
        mapper->getSerializer()->getConfig()->includeNullFields = false;
        mapper->getDeserializer()->getConfig()->allowUnknownFields = true;
        return mapper;
    }());

    OATPP_CREATE_COMPONENT(
        std::shared_ptr<oatpp::network::ServerConnectionProvider>,
        serverConnectionProvider)([] {
        OATPP_COMPONENT(std::shared_ptr<OrchestratorConfig>, cfg);
        return oatpp::network::tcp::server::ConnectionProvider::createShared(
            {cfg->listen_addr.c_str(),
             static_cast<v_uint16>(cfg->port),
             oatpp::network::Address::IP_4});
    }());

    OATPP_CREATE_COMPONENT(
        std::shared_ptr<oatpp::web::server::HttpRouter>, httpRouter)([] {
        return oatpp::web::server::HttpRouter::createShared();
    }());
};

#pragma once

#include "../db/DbClient.hpp"
#include "../auth/JwtService.hpp"
#include "../dto/Dtos.hpp"
#include "oatpp/core/macro/component.hpp"
#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

#include OATPP_CODEGEN_BEGIN(ApiController)

class NodeController : public oatpp::web::server::api::ApiController {
public:
    NodeController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper))
        : ApiController(objectMapper), m_jwt(std::make_unique<JwtService>()) {}

    static std::shared_ptr<NodeController> createShared(
            OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) {
        return std::make_shared<NodeController>(objectMapper);
    }

    // ── POST /api/v1/nodes/register ──────────────────────────────────────────

    ENDPOINT_INFO(registerNode) {
        info->summary     = "Register a honeypot node";
        info->description =
            "Register a new honeypot node (or re-register an existing one). "
            "Returns a signed JWT that must be used as Bearer token for all "
            "subsequent authenticated requests.";
        info->tags.push_back("Nodes");
        info->addConsumes<Object<NodeRegisterDto>>("application/json");
        info->addResponse<Object<NodeRegisterResponseDto>>(
            Status::CODE_200, "application/json");
        info->addResponse<Object<StatusDto>>(
            Status::CODE_400, "application/json");
    }
    ENDPOINT("POST", "/api/v1/nodes/register", registerNode,
             BODY_DTO(Object<NodeRegisterDto>, body)) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        if (!body || !body->node_id || !body->api_key) {
            return createResponse(Status::CODE_400, "node_id and api_key required");
        }
        std::string nid    = body->node_id->c_str();
        std::string region = body->region     ? body->region->c_str()     : "";
        std::string ip     = body->ip_address ? body->ip_address->c_str() : "";
        std::string keyHash = sha256(body->api_key->c_str());
        db->registerNode(nid, region, ip, keyHash);

        std::string jwt = m_jwt->createNodeToken(nid, region);
        auto resp      = NodeRegisterResponseDto::createShared();
        resp->node_id   = nid;
        resp->jwt_token = jwt;
        resp->message   = "Node registered successfully";
        return createDtoResponse(Status::CODE_200, resp);
    }

    // ── GET /api/v1/nodes ────────────────────────────────────────────────────

    ENDPOINT_INFO(listNodes) {
        info->summary     = "List all registered nodes";
        info->description = "Returns all honeypot nodes known to the orchestrator.";
        info->tags.push_back("Nodes");
        info->addResponse<List<Object<NodeDto>>>(Status::CODE_200, "application/json");
    }
    ENDPOINT("GET", "/api/v1/nodes", listNodes) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        auto nodes = db->listNodes();
        auto list  = oatpp::List<oatpp::Object<NodeDto>>::createShared();
        for (auto& n : nodes) list->push_back(n);
        return createDtoResponse(Status::CODE_200, list);
    }

private:
    std::unique_ptr<JwtService> m_jwt;

    static std::string sha256(const std::string& input) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int  len = 0;
        EVP_MD_CTX*   ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, input.data(), input.size());
        EVP_DigestFinal_ex(ctx, hash, &len);
        EVP_MD_CTX_free(ctx);
        std::ostringstream ss;
        for (unsigned int i = 0; i < len; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        return ss.str();
    }
};

#include OATPP_CODEGEN_END(ApiController)

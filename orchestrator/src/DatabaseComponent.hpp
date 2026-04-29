#pragma once

#include "ConfigComponent.hpp"
#include "db/DbClient.hpp"
#include "oatpp/core/macro/component.hpp"

/// Registers the shared DbClient as an Oat++ DI component.
/// Controllers use OATPP_COMPONENT(std::shared_ptr<DbClient>, m_db)
/// to inject it automatically.
class DatabaseComponent {
public:
    OATPP_CREATE_COMPONENT(std::shared_ptr<DbClient>, dbClient)([] {
        OATPP_COMPONENT(std::shared_ptr<OrchestratorConfig>, cfg);
        auto db = std::make_shared<DbClient>(cfg);
        db->runMigration("sql/001_initial.sql");
        return db;
    }());
};

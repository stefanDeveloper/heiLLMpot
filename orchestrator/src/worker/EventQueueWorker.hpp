#pragma once

#include "../db/DbClient.hpp"
#include "../ConfigComponent.hpp"
#include "oatpp/core/macro/component.hpp"

#include <atomic>
#include <thread>
#include <memory>
#include <vector>
#include <mutex>
#include <condition_variable>

class EventQueueWorker {
public:
    explicit EventQueueWorker(std::shared_ptr<DbClient> db);
    ~EventQueueWorker();

    void start();
    void stop();

    void enqueue(const ScanEventData& event);

private:
    void loop();

    std::shared_ptr<DbClient>  m_db;
    std::atomic<bool>          m_running{false};
    std::thread                m_thread;

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<ScanEventData> m_queue;
    size_t m_max_size = 10000;
};

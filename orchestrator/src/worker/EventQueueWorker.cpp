#include "EventQueueWorker.hpp"
#include "oatpp/core/base/Environment.hpp"
#include <iostream>

EventQueueWorker::EventQueueWorker(std::shared_ptr<DbClient> db)
    : m_db(std::move(db)) {}

EventQueueWorker::~EventQueueWorker() { stop(); }

void EventQueueWorker::start() {
    m_running = true;
    m_thread  = std::thread(&EventQueueWorker::loop, this);
    OATPP_LOGI("Worker", "EventQueueWorker started");
}

void EventQueueWorker::stop() {
    m_running = false;
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

void EventQueueWorker::enqueue(const ScanEventData& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_queue.size() >= m_max_size) {
        // Load shedding: drop event if queue is full
        return;
    }
    m_queue.push_back(event);
    m_cv.notify_one();
}

void EventQueueWorker::loop() {
    while (m_running) {
        std::vector<ScanEventData> batch;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(1), [this]() {
                return !m_running || !m_queue.empty();
            });

            if (!m_running && m_queue.empty()) {
                break;
            }

            // Move queue contents to batch
            batch = std::move(m_queue);
            m_queue.clear();
        }

        if (!batch.empty()) {
            try {
                m_db->insertEventsBatch(batch);
            } catch (const std::exception& e) {
                OATPP_LOGE("Worker", "Error inserting event batch: %s", e.what());
            }
        }
    }
}

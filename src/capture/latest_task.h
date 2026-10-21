#pragma once
#include <QString>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

namespace etherscope {
// One active job and one replaceable pending job. Results need request/error members.
// Notifications may originate on either thread; owners use queued Qt connections.
template<class Input,class Result> class LatestTask {
public:
    using Work=std::function<Result(Input,std::stop_token)>;
    LatestTask(Work work,std::function<void()> notify):work_(std::move(work)),notify_(std::move(notify)),
        thread_([this](std::stop_token stop){run(stop);}) {}
    ~LatestTask(){stop();if(thread_.joinable())thread_.join();}
    std::uint64_t request(Input input) {
        std::stop_source previous;std::uint64_t id;
        {std::lock_guard lock(mutex_);if(stopped_)return 0;id=++generation_;previous=activeStop_;completed_.reset();pending_=Job{id,std::move(input)};}
        previous.request_stop();wake_.notify_one();return id;
    }
    void cancel() {
        std::stop_source previous;
        {std::lock_guard lock(mutex_);++generation_;previous=activeStop_;pending_.reset();completed_.reset();}
        previous.request_stop();
    }
    void stop() {
        {std::lock_guard lock(mutex_);stopped_=true;}
        cancel();thread_.request_stop();wake_.notify_all();
    }
    bool busy() const {std::lock_guard lock(mutex_);return working_ || pending_.has_value();}
    std::optional<Result> take() {std::lock_guard lock(mutex_);auto result=std::move(completed_);completed_.reset();return result;}
private:
    struct Job {std::uint64_t id{};Input input;};
    Work work_;
    std::function<void()> notify_;
    mutable std::mutex mutex_;
    std::condition_variable_any wake_;
    std::optional<Job> pending_;
    std::optional<Result> completed_;
    bool working_{},stopped_{};
    std::uint64_t generation_{};
    std::stop_source activeStop_;
    std::jthread thread_;
    void run(std::stop_token stop) {
        for(;;) {
            std::optional<Job> job;std::stop_token token;
            {
                std::unique_lock lock(mutex_);
                if(!wake_.wait(lock,stop,[this]{return pending_.has_value();}))break;
                job=std::move(pending_);pending_.reset();working_=true;activeStop_=std::stop_source{};token=activeStop_.get_token();
            }
            Result result;
            try{result=work_(std::move(job->input),token);}
            catch(const std::exception& error){result.error=QString::fromUtf8(error.what());}
            result.request=job->id;job.reset();
            {
                std::lock_guard lock(mutex_);working_=false;
                if(!stopped_ && !stop.stop_requested() && result.request==generation_)completed_=std::move(result);
            }
            notify_();
        }
        notify_();
    }
};
}

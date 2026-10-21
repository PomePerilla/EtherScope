#include "core/application_index.h"
#include <algorithm>

namespace etherscope {
void ApplicationIndex::clear(){entries_.clear();facts_.clear();order_.clear();bytes_=0;}
const ApplicationFacts* ApplicationIndex::facts(std::uint64_t id) const {const auto it=facts_.find(id);return it==facts_.end()?nullptr:&it->second;}
void ApplicationIndex::apply(std::uint64_t conversation,std::shared_ptr<const ApplicationResult> result,std::map<std::uint64_t,ApplicationFacts> facts) {
    if(facts.empty())return;
    const auto key=std::pair{conversation!=0,conversation?conversation:facts.begin()->first};
    if(auto old=entries_.find(key);old!=entries_.end()){bytes_-=old->second.bytes;for(auto id:old->second.packets)facts_.erase(id);entries_.erase(old);std::erase(order_,key);}
    Entry entry;entry.result=std::move(result);entry.bytes=sizeof(Entry)+(entry.result?entry.result->estimatedBytes:0);
    for(auto& [id,value]:facts){entry.packets.push_back(id);entry.bytes+=sizeof(ApplicationFacts)+96;for(const auto& [name,values]:value.values){entry.bytes+=name.capacity()+96+values.capacity()*sizeof(ApplicationValue);for(const auto& v:values)if(const auto* text=std::get_if<std::string>(&v))entry.bytes+=text->capacity();}facts_[id]=std::move(value);}
    entry.bytes+=entry.packets.capacity()*sizeof(std::uint64_t);bytes_+=entry.bytes;entries_[key]=std::move(entry);order_.push_back(key);
    while(bytes_>applicationBudget/2 && !order_.empty()) {
        const auto oldest=order_.front();order_.pop_front();auto found=entries_.find(oldest);if(found==entries_.end())continue;
        bytes_-=found->second.bytes;for(auto id:found->second.packets){auto& f=facts_[id];f.values.clear();f.status=AnalysisStatus::Limited;}entries_.erase(found);
    }
}
void ApplicationIndex::prune(std::uint64_t first,std::uint64_t last) {
    for(auto it=facts_.begin();it!=facts_.end();)if(!first || it->first<first || it->first>last)it=facts_.erase(it);else ++it;
    for(auto it=entries_.begin();it!=entries_.end();) {
        std::erase_if(it->second.packets,[&](auto id){return !facts_.contains(id);});
        if(it->second.packets.empty()){bytes_-=it->second.bytes;std::erase(order_,it->first);it=entries_.erase(it);}else ++it;
    }
}
std::vector<std::shared_ptr<const ApplicationResult>> ApplicationIndex::results(std::uint64_t packet) const {
    std::vector<std::shared_ptr<const ApplicationResult>> result;
    for(const auto& [key,entry]:entries_){(void)key;if(entry.result && std::binary_search(entry.packets.begin(),entry.packets.end(),packet))result.push_back(entry.result);}
    return result;
}
std::vector<std::shared_ptr<const ApplicationResult>> ApplicationIndex::conversation(std::uint64_t id) const {const auto it=entries_.find({true,id});return it==entries_.end()?std::vector<std::shared_ptr<const ApplicationResult>>{}:std::vector{it->second.result};}
std::pair<std::size_t,std::size_t> ApplicationIndex::unresolved() const {std::size_t pending=0,incomplete=0;for(const auto& [id,f]:facts_){(void)id;if(f.status==AnalysisStatus::Pending)++pending;else if(f.status!=AnalysisStatus::Complete)++incomplete;}return {pending,incomplete};}
}

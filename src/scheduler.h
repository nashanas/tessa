// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2017 The PIVX developers
// Copyright (c) 2018 The TessaChain developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#pragma once

//
// NOTE:
// std::thread / std::function / std::chrono now we support C++11.
//
#include <thread>
#include <functional>
#include <map>
#include <chrono>
#include <condition_variable>
//
// Simple class for background tasks that should be run
// periodically or once "after a while"
//
// Usage:
//
// CScheduler* s = new CScheduler();
// s->scheduleFromNow(doSomething, 11); // Assuming a: void doSomething() { }
// s->scheduleFromNow(boost::bind(Class::func, this, argument), 3);
// boost::thread* t = new boost::thread(boost::bind(CScheduler::serviceQueue, s));
//
// ... then at program shutdown, clean up the thread running serviceQueue:
// t->interrupt();
// t->join();
// delete t;
// delete s; // Must be done after thread is interrupted/joined.
//

class CScheduler {
 public:
  CScheduler();
  ~CScheduler();

  typedef std::function<void(void)> Function;

  // Call func at/after time t
  void schedule(Function f, std::chrono::system_clock::time_point t);

  // Convenience method: call f once deltaSeconds from now
  void scheduleFromNow(Function f, int64_t deltaSeconds);

  // Another convenience method: call f approximately
  // every deltaSeconds forever, starting deltaSeconds from now.
  // To be more precise: every time f is finished, it
  // is rescheduled to run deltaSeconds later. If you
  // need more accurate scheduling, don't use this method.
  void scheduleEvery(Function f, int64_t deltaSeconds);

  // To keep things as simple as possible, there is no unschedule.

  // Services the queue 'forever'. Should be run in a thread,
  // and interrupted using boost::interrupt_thread
  void serviceQueue();

  // Tell any threads running serviceQueue to stop as soon as they're
  // done servicing whatever task they're currently servicing (drain=false)
  // or when there is no work left to be done (drain=true)
  void stop(bool drain = false);

  // Returns number of tasks waiting to be serviced,
  // and first and last task times
  size_t getQueueInfo(std::chrono::system_clock::time_point &first,
                      std::chrono::system_clock::time_point &last) const;

 private:
  std::multimap<std::chrono::system_clock::time_point, Function> taskQueue;
  std::condition_variable newTaskScheduled;
  mutable std::mutex newTaskMutex;
  int nThreadsServicingQueue;
  bool stopRequested;
  bool stopWhenEmpty;
  bool shouldStop() { return stopRequested || (stopWhenEmpty && taskQueue.empty()); }
};


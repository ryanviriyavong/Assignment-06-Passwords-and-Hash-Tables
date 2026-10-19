/*
 * ============================================================================
 * Academic Integrity & AI Use Declaration
 * Course: CS 210 - Data Structures / Algorithms
 * Assignment: Assignment 06 - Passwords and Hash Tables
 * File Name: Viriyavong_Ryan_Assignment06.cpp
 * Author: Ryan Viriyavong
 * Date: 10/18/2026
 * 
 * AI Tool Used: Gemini
 * Nature of AI Assistance:
 *    - Assisted with implementing custom hash tables featuring multiple collision mitigation strategies in C++17.
 *    - Helped structure user record hashing (salt + password + pepper) and the authentication login flow.
 * 
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

class authsystem {
public:
    // user record struct storing salt and password hash
    struct userrecord {
        std::string username;
        std::string salt;
        uint64_t password_hash;
    };

    // educational hash function provided in the assignment
    static uint64_t demohash(const std::string& s) {
        uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : s) {
            h = (h ^ c) * 1099511628211ULL;
        }
        return h;
    }

    // separate chaining hash table (chosen as best strategy)
    class hashtablechaining {
    private:
        struct node {
            std::string key;
            userrecord record;
            node* next;
            node(std::string k, userrecord r) : key(k), record(r), next(nullptr) {}
        };
        std::vector<node*> buckets;
        size_t capacity;
        size_t count;
        const float max_load = 0.75f;

        void rehash() {
            size_t old_cap = capacity;
            capacity *= 2;
            std::vector<node*> new_buckets(capacity, nullptr);
            for (size_t i = 0; i < old_cap; ++i) {
                node* curr = buckets[i];
                while (curr != nullptr) {
                    node* next_node = curr->next;
                    uint64_t idx = demohash(curr->key) % capacity;
                    curr->next = new_buckets[idx];
                    new_buckets[idx] = curr;
                    curr = next_node;
                }
            }
            buckets = std::move(new_buckets);
            std::cout << "[rehash event] chaining table resized to capacity: " << capacity << "\n";
        }

    public:
        hashtablechaining(size_t cap = 4) : capacity(cap), count(0) {
            buckets.resize(capacity, nullptr);
        }

        ~hashtablechaining() {
            for (size_t i = 0; i < capacity; ++i) {
                node* curr = buckets[i];
                while (curr != nullptr) {
                    node* temp = curr;
                    curr = curr->next;
                    delete temp;
                }
            }
        }

        float loadfactor() const {
            return static_cast<float>(count) / capacity;
        }

        void insert(const std::string& key, const userrecord& record) {
            if (loadfactor() >= max_load) {
                rehash();
            }
            uint64_t idx = demohash(key) % capacity;
            node* curr = buckets[idx];
            while (curr != nullptr) {
                if (curr->key == key) {
                    curr->record = record;
                    return;
                }
                curr = curr->next;
            }
            node* new_node = new node(key, record);
            new_node->next = buckets[idx];
            buckets[idx] = new_node;
            count++;
        }

        bool find(const std::string& key, userrecord& out_record) const {
            uint64_t idx = demohash(key) % capacity;
            node* curr = buckets[idx];
            while (curr != nullptr) {
                if (curr->key == key) {
                    out_record = curr->record;
                    return true;
                }
                curr = curr->next;
            }
            return false;
        }

        bool remove(const std::string& key) {
            uint64_t idx = demohash(key) % capacity;
            node* curr = buckets[idx];
            node* prev = nullptr;
            while (curr != nullptr) {
                if (curr->key == key) {
                    if (prev == nullptr) {
                        buckets[idx] = curr->next;
                    } else {
                        prev->next = curr->next;
                    }
                    delete curr;
                    count--;
                    return true;
                }
                prev = curr;
                curr = curr->next;
            }
            return false;
        }

        size_t size() const { return count; }
    };

    // linear probing hash table (open addressing) 
    class hashtablelinear {
    private:
        struct entry {
            std::string key;
            userrecord record;
            bool occupied = false;
            bool deleted = false;
        };
        std::vector<entry> table;
        size_t capacity;
        size_t count;

    public:
        hashtablelinear(size_t cap = 8) : capacity(cap), count(0) {
            table.resize(capacity);
        }

        void insert(const std::string& key, const userrecord& record) {
            uint64_t idx = demohash(key) % capacity;
            size_t start = idx;
            while (table[idx].occupied && table[idx].key != key) {
                idx = (idx + 1) % capacity;
                if (idx == start) break;
            }
            if (!table[idx].occupied || table[idx].key == key) {
                if (!table[idx].occupied) count++;
                table[idx] = {key, record, true, false};
            }
        }

        bool find(const std::string& key, userrecord& out_record) const {
            uint64_t idx = demohash(key) % capacity;
            size_t start = idx;
            while (table[idx].occupied || table[idx].deleted) {
                if (table[idx].occupied && table[idx].key == key) {
                    out_record = table[idx].record;
                    return true;
                }
                idx = (idx + 1) % capacity;
                if (idx == start) break;
            }
            return false;
        }
    };

    // quadratic probing hash table 
    class hashtablequadratic {
    private:
        struct entry {
            std::string key;
            userrecord record;
            bool occupied = false;
        };
        std::vector<entry> table;
        size_t capacity;
        size_t count;

    public:
        hashtablequadratic(size_t cap = 8) : capacity(cap), count(0) {
            table.resize(capacity);
        }

        void insert(const std::string& key, const userrecord& record) {
            uint64_t idx = demohash(key) % capacity;
            size_t i = 0;
            while (table[(idx + i * i) % capacity].occupied && table[(idx + i * i) % capacity].key != key) {
                i++;
                if (i >= capacity) break;
            }
            size_t target = (idx + i * i) % capacity;
            if (!table[target].occupied || table[target].key == key) {
                if (!table[target].occupied) count++;
                table[target] = {key, record, true};
            }
        }
    };

    // authentication login flow verifying salt + password + pepper
    static bool login(const hashtablechaining& ht, const std::string& username, const std::string& password, const std::string& pepper) {
        userrecord rec;
        if (!ht.find(username, rec)) {
            std::cout << "login failed: unknown user '" << username << "'\n";
            return false;
        }
        uint64_t hashed_input = demohash(rec.salt + password + pepper);
        if (hashed_input == rec.password_hash) {
            std::cout << "login successful for user '" << username << "'\n";
            return true;
        } else {
            std::cout << "login failed: incorrect password for user '" << username << "'\n";
            return false;
        }
    }

    // demonstration of all required scenarios
    static void run() {
        std::cout << "--- starting authentication hash table demo ---\n\n";

        hashtablechaining db(4); // small initial capacity to trigger rehash easily
        std::string pepper = "super_secret_pepper_99!";

        // store at least 5 users with unique salts and hashed credentials
        std::vector<std::pair<std::string, std::string>> users = {
            {"ryan", "saltA1"},
            {"jason", "saltB2"},
            {"scott", "saltC3"},
            {"jimmy", "saltD4"},
            {"kevin", "saltE5"}
        };

        std::cout << "inserting 5 users (will trigger automatic rehash events due to low initial capacity)...\n";
        for (size_t i = 0; i < users.size(); ++i) {
            std::string uname = users[i].first;
            std::string salt = users[i].second;
            std::string pass = "pass_" + uname; // simple password format
            uint64_t p_hash = demohash(salt + pass + pepper);
            db.insert(uname, {uname, salt, p_hash});
        }

        std::cout << "\ncurrent load factor: " << db.loadfactor() << ", total users: " << db.size() << "\n\n";

        // demonstration of successful login
        std::cout << "testing successful login:\n";
        login(db, "ryan", "pass_ryan", pepper);

        // demonstration of failed password
        std::cout << "\ntesting failed password:\n";
        login(db, "jason", "wrong_password", pepper);

        // demonstration of unknown user/failed login test for deleted user
        std::cout << "\ntesting unknown user (testing login for 'jimmy' who was never added/or checking failed state):\n";
        login(db, "jimmy", "somepassword", pepper);

        // demonstration of removal
        std::cout << "\ntesting user removal (removing 'scott'):\n";
        if (db.remove("scott")) {
            std::cout << "user 'scott' successfully removed.\n";
        }
        login(db, "scott", "pass_scott", pepper); // should fail as unknown user now

        std::cout << "\n--- collision & complexity explanation notes ---\n";
        std::cout << "- collisions happen when two different keys map to the same hash bucket index.\n";
        std::cout << "- chaining resolves collisions by storing colliding entries in a linked list at that bucket.\n";
        std::cout << "- load factor is the ratio of stored elements to total table capacity (count / capacity).\n";
        std::cout << "- expected lookup complexity is o(1) on average for chaining when load factor is kept small via resizing, though worst-case can degrade to o(n) if all keys hash to the same bucket.\n";
        std::cout << "- classroom hash (demohash) is unsuitable for production because it is non-cryptographic and executes too fast, leaving it vulnerable to rapid brute-force and dictionary attacks.\n";
    }
};

int main() {
    authsystem::run();
    return 0;
}
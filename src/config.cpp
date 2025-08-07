#include "config.h"
#include "core/exception.h"

namespace loki::config {
    Config::Config() {
        _settings["version"] = SDK_VERSION;
        _settings["version_major"] = std::to_string(SDK_VERSION_MAJOR);
        _settings["version_minor"] = std::to_string(SDK_VERSION_MINOR);
        _settings["version_patch"] = std::to_string(SDK_VERSION_PATCH);
        _settings["default_key_size"] = std::to_string(DEFAULT_KEY_SIZE);
        _settings["default_buffer_size"] = std::to_string(DEFAULT_BUFFER_SIZE);
        _settings["default_iterations"] = std::to_string(DEFAULT_ITERATIONS);
    }

    void Config::set(const std::string& key, const std::string& value) {
        _settings[key] = value;
    }

    std::string Config::get(const std::string& key) const {
        auto it = _settings.find(key);
        if (it == _settings.end()) {
            throw core::InvalidArgumentException("Configuration key not found: " + key);
        }
        return it->second;
    }

    std::string Config::get(const std::string& key, const std::string& default_value) const {
        auto it = _settings.find(key);
        return (it != _settings.end()) ? it->second : default_value;
    }

    bool Config::has(const std::string& key) const {
        return _settings.find(key) != _settings.end();
    }

    void Config::remove(const std::string& key) {
        _settings.erase(key);
    }

    void Config::clear() {
        _settings.clear();
    }

    Config& Config::instance() {
        static Config instance;
        return instance;
    }
}
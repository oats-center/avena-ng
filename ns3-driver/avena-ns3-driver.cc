#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/propagation-module.h"
#include "ns3/spectrum-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/wifi-module.h"

using json = nlohmann::json;
using namespace ns3;

namespace {

struct MobilityTracePoint {
    double time_s;
    double x_m;
    double y_m;
    double z_m;
};

struct RuntimeMobility {
    std::string type;
    std::string path;
    double x_m = 0.0;
    double y_m = 0.0;
    double z_m = 0.0;
};

struct RuntimeRadio {
    std::string id;
    std::optional<std::string> profile;
    std::optional<std::string> kind;
    std::optional<std::string> phy_backend;
    std::optional<std::string> standard;
    std::optional<std::string> band;
    std::optional<uint32_t> channel;
    std::optional<uint32_t> channel_width_mhz;
    std::optional<float> tx_power_dbm;
    std::optional<float> rx_noise_figure_db;
    std::optional<std::string> propagation;
};

struct RuntimeNode {
    std::string id;
    RuntimeMobility mobility;
    std::vector<RuntimeRadio> radios;
};

struct RuntimeEndpoint {
    std::string node_id;
    std::string radio_id;
    std::string ns_if;
    std::string tap_if;
    std::string underlay_ipv4;
};

struct RuntimeLink {
    std::string id;
    std::optional<std::string> medium;
    std::array<RuntimeEndpoint, 2> endpoints;
};

struct RuntimeBridge {
    std::string id;
    std::optional<std::string> medium;
    std::vector<RuntimeEndpoint> members;
};

struct RuntimeConfig {
    std::string scenario_name;
    uint64_t duration_secs = 0;
    uint32_t realtime_hard_limit_ms = 250;
    bool emit_pcap = false;
    std::vector<RuntimeNode> nodes;
    std::vector<RuntimeLink> links;
    std::vector<RuntimeBridge> bridges;
};

struct WirelessNetwork {
    std::string id;
    std::vector<RuntimeEndpoint> members;
};

template <typename T>
T JsonRequired(const json& obj, const char* key) {
    if (!obj.contains(key) || obj.at(key).is_null()) {
        throw std::runtime_error(std::string("missing required key: ") + key);
    }
    return obj.at(key).get<T>();
}

template <typename T>
std::optional<T> JsonOptional(const json& obj, const char* key) {
    if (!obj.contains(key) || obj.at(key).is_null()) {
        return std::nullopt;
    }
    return obj.at(key).get<T>();
}

std::string Trim(std::string value) {
    const char* whitespace = " \t\r\n";
    const auto begin = value.find_first_not_of(whitespace);
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(whitespace);
    return value.substr(begin, end - begin + 1);
}

std::vector<MobilityTracePoint> LoadTraceCsv(const std::string& path) {
    std::ifstream input(path);
    if (!input.good()) {
        throw std::runtime_error("failed to open mobility trace: " + path);
    }

    std::vector<MobilityTracePoint> points;
    std::string line;
    size_t line_no = 0;
    while (std::getline(input, line)) {
        ++line_no;
        const std::string cleaned = Trim(line);
        if (cleaned.empty() || cleaned[0] == '#') {
            continue;
        }

        std::stringstream ss(cleaned);
        std::string cell;
        std::vector<std::string> parts;
        while (std::getline(ss, cell, ',')) {
            parts.push_back(Trim(cell));
        }

        if (parts.size() != 4) {
            throw std::runtime_error("invalid mobility trace row at line " + std::to_string(line_no) + " in " + path);
        }

        MobilityTracePoint point{};
        point.time_s = std::stod(parts[0]);
        point.x_m = std::stod(parts[1]);
        point.y_m = std::stod(parts[2]);
        point.z_m = std::stod(parts[3]);
        points.push_back(point);
    }

    if (points.empty()) {
        throw std::runtime_error("mobility trace is empty: " + path);
    }

    return points;
}

RuntimeConfig ParseRuntimeConfig(const std::string& path) {
    std::ifstream input(path);
    if (!input.good()) {
        throw std::runtime_error("failed to open runtime config: " + path);
    }

    json root;
    input >> root;

    RuntimeConfig cfg;
    cfg.scenario_name = JsonRequired<std::string>(root, "scenario_name");
    cfg.duration_secs = JsonRequired<uint64_t>(root, "duration_secs");
    cfg.realtime_hard_limit_ms = JsonRequired<uint32_t>(root, "realtime_hard_limit_ms");
    cfg.emit_pcap = JsonRequired<bool>(root, "emit_pcap");

    for (const auto& node_json : JsonRequired<json>(root, "nodes")) {
        RuntimeNode node;
        node.id = JsonRequired<std::string>(node_json, "id");

        const auto mobility_json = JsonRequired<json>(node_json, "mobility");
        node.mobility.type = JsonRequired<std::string>(mobility_json, "type");
        if (node.mobility.type == "trace") {
            node.mobility.path = JsonRequired<std::string>(mobility_json, "path");
        } else if (node.mobility.type == "fixed") {
            node.mobility.x_m = JsonRequired<double>(mobility_json, "x_m");
            node.mobility.y_m = JsonRequired<double>(mobility_json, "y_m");
            node.mobility.z_m = JsonRequired<double>(mobility_json, "z_m");
        } else {
            throw std::runtime_error("unsupported mobility type for node '" + node.id + "': " + node.mobility.type);
        }

        for (const auto& radio_json : JsonRequired<json>(node_json, "radios")) {
            RuntimeRadio radio;
            radio.id = JsonRequired<std::string>(radio_json, "id");
            radio.profile = JsonOptional<std::string>(radio_json, "profile");
            radio.kind = JsonOptional<std::string>(radio_json, "kind");
            radio.phy_backend = JsonOptional<std::string>(radio_json, "phy_backend");
            radio.standard = JsonOptional<std::string>(radio_json, "standard");
            radio.band = JsonOptional<std::string>(radio_json, "band");
            radio.channel = JsonOptional<uint32_t>(radio_json, "channel");
            radio.channel_width_mhz = JsonOptional<uint32_t>(radio_json, "channel_width_mhz");
            radio.tx_power_dbm = JsonOptional<float>(radio_json, "tx_power_dbm");
            radio.rx_noise_figure_db = JsonOptional<float>(radio_json, "rx_noise_figure_db");
            radio.propagation = JsonOptional<std::string>(radio_json, "propagation");
            node.radios.push_back(radio);
        }

        cfg.nodes.push_back(node);
    }

    for (const auto& link_json : JsonRequired<json>(root, "links")) {
        RuntimeLink link;
        link.id = JsonRequired<std::string>(link_json, "id");
        link.medium = JsonOptional<std::string>(link_json, "medium");
        const auto endpoints = JsonRequired<json>(link_json, "endpoints");
        if (endpoints.size() != 2) {
            throw std::runtime_error("link '" + link.id + "' must contain exactly two endpoints");
        }

        for (size_t i = 0; i < 2; ++i) {
            RuntimeEndpoint endpoint;
            endpoint.node_id = JsonRequired<std::string>(endpoints.at(i), "node_id");
            endpoint.radio_id = JsonRequired<std::string>(endpoints.at(i), "radio_id");
            endpoint.ns_if = JsonRequired<std::string>(endpoints.at(i), "ns_if");
            endpoint.tap_if = JsonRequired<std::string>(endpoints.at(i), "tap_if");
            endpoint.underlay_ipv4 = JsonRequired<std::string>(endpoints.at(i), "underlay_ipv4");
            link.endpoints.at(i) = endpoint;
        }

        cfg.links.push_back(link);
    }

    for (const auto& bridge_json : JsonRequired<json>(root, "bridges")) {
        RuntimeBridge bridge;
        bridge.id = JsonRequired<std::string>(bridge_json, "id");
        bridge.medium = JsonOptional<std::string>(bridge_json, "medium");
        for (const auto& member_json : JsonRequired<json>(bridge_json, "members")) {
            RuntimeEndpoint endpoint;
            endpoint.node_id = JsonRequired<std::string>(member_json, "node_id");
            endpoint.radio_id = JsonRequired<std::string>(member_json, "radio_id");
            endpoint.ns_if = JsonRequired<std::string>(member_json, "ns_if");
            endpoint.tap_if = JsonRequired<std::string>(member_json, "tap_if");
            endpoint.underlay_ipv4 = JsonRequired<std::string>(member_json, "underlay_ipv4");
            bridge.members.push_back(endpoint);
        }
        cfg.bridges.push_back(bridge);
    }

    return cfg;
}

std::string RadioKey(const std::string& node_id, const std::string& radio_id) {
    return node_id + ":" + radio_id;
}

std::string NormalizeLower(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return value;
}

json BuildRealtimeEvent(uint64_t sim_ms, uint64_t wall_ms, int64_t lag_ms) {
    return json{{"type", "realtime"},
                {"sim_ms", sim_ms},
                {"wall_ms", wall_ms},
                {"lag_ms", lag_ms}};
}

class AvenaNs3Driver {
  public:
    explicit AvenaNs3Driver(RuntimeConfig cfg)
        : m_cfg(std::move(cfg)) {}

    void Initialize() {
        ConfigureRealtimeSimulator();
        BuildNodeIndex();
        InstallMobilityModels();
        InstallWirelessNetworks();
        ScheduleMobilityTelemetry();
        ScheduleRealtimeTelemetry();
    }

    int Run(uint64_t duration_override_secs) {
        const uint64_t duration_secs =
            duration_override_secs > 0 ? duration_override_secs : m_cfg.duration_secs;
        Simulator::Stop(Seconds(static_cast<double>(duration_secs)));
        Simulator::Run();
        Simulator::Destroy();

        if (m_realtime_hard_limit_exceeded) {
            return 3;
        }
        return 0;
    }

  private:
    void ConfigureRealtimeSimulator() {
        GlobalValue::Bind("SimulatorImplementationType",
                          StringValue("ns3::RealtimeSimulatorImpl"));
        GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));
        m_wall_start = std::chrono::steady_clock::now();
    }

    void BuildNodeIndex() {
        for (const auto& node_cfg : m_cfg.nodes) {
            Ptr<Node> node = CreateObject<Node>();
            m_nodes.emplace(node_cfg.id, node);

            for (const auto& radio : node_cfg.radios) {
                m_radios.emplace(RadioKey(node_cfg.id, radio.id), radio);
            }
        }
    }

    void InstallMobilityModels() {
        for (const auto& node_cfg : m_cfg.nodes) {
            const auto it = m_nodes.find(node_cfg.id);
            if (it == m_nodes.end()) {
                throw std::runtime_error("missing ns3 node for mobility install: " + node_cfg.id);
            }

            Ptr<Node> node = it->second;
            if (node_cfg.mobility.type == "trace") {
                auto points = LoadTraceCsv(node_cfg.mobility.path);
                Ptr<WaypointMobilityModel> mobility = CreateObject<WaypointMobilityModel>();
                for (const auto& point : points) {
                    mobility->AddWaypoint(Waypoint(
                        Seconds(point.time_s),
                        Vector(point.x_m, point.y_m, point.z_m)));
                }
                node->AggregateObject(mobility);
            } else {
                Ptr<ConstantPositionMobilityModel> mobility = CreateObject<ConstantPositionMobilityModel>();
                mobility->SetPosition(
                    Vector(node_cfg.mobility.x_m, node_cfg.mobility.y_m, node_cfg.mobility.z_m));
                node->AggregateObject(mobility);
            }
        }
    }

    void InstallWirelessNetworks() {
        std::vector<WirelessNetwork> networks;
        for (const auto& link : m_cfg.links) {
            if (NormalizeLower(link.medium.value_or("wifi")) != "wifi") {
                continue;
            }
            networks.push_back(WirelessNetwork{
                link.id,
                std::vector<RuntimeEndpoint>{link.endpoints.at(0), link.endpoints.at(1)},
            });
        }

        for (const auto& bridge : m_cfg.bridges) {
            if (NormalizeLower(bridge.medium.value_or("wifi")) != "wifi") {
                continue;
            }
            networks.push_back(WirelessNetwork{bridge.id, bridge.members});
        }

        std::unordered_set<std::string> attached_radios;
        for (const auto& network : networks) {
            for (const auto& endpoint : network.members) {
                const std::string key = RadioKey(endpoint.node_id, endpoint.radio_id);
                if (!attached_radios.insert(key).second) {
                    throw std::runtime_error(
                        "radio assigned to multiple wireless networks: " + key);
                }
            }
            InstallNetwork(network);
        }
    }

    void InstallNetwork(const WirelessNetwork& network) {
        if (network.members.empty()) {
            return;
        }

        const RuntimeRadio& first_radio = ResolveRadio(network.members.front());
        const std::string phy_backend = NormalizeLower(first_radio.phy_backend.value_or("spectrum"));
        const std::string band = NormalizeLower(first_radio.band.value_or("5ghz"));
        const uint32_t channel = first_radio.channel.value_or(0);
        const std::string propagation = NormalizeLower(first_radio.propagation.value_or("log-distance"));

        WifiHelper wifi;
        wifi.SetRemoteStationManager("ns3::MinstrelHtWifiManager");

        WifiMacHelper mac;
        mac.SetType("ns3::AdhocWifiMac");

        if (phy_backend == "yans") {
            YansWifiChannelHelper channel_helper;
            channel_helper.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
            ConfigureYansPropagation(channel_helper, propagation);
            Ptr<YansWifiChannel> yans_channel = channel_helper.Create();

            for (const auto& endpoint : network.members) {
                const RuntimeRadio& radio = ResolveRadio(endpoint);
                ValidateRadioCompatibility(first_radio, radio, endpoint);

                YansWifiPhyHelper phy;
                phy.SetChannel(yans_channel);
                ApplyPhyAttributes(phy, radio);

                Ptr<Node> node = ResolveNode(endpoint.node_id);
                NodeContainer node_container;
                node_container.Add(node);
                NetDeviceContainer devices = wifi.Install(phy, mac, node_container);

                if (devices.GetN() != 1) {
                    throw std::runtime_error("failed to create wifi device for endpoint " +
                                             RadioKey(endpoint.node_id, endpoint.radio_id));
                }

                const std::string key = RadioKey(endpoint.node_id, endpoint.radio_id);
                m_radio_devices.emplace(key, devices.Get(0));
                AttachTap(endpoint, devices.Get(0));
                EmitL2Ready(endpoint, network.id, band, channel);
            }
            return;
        }

        const std::string spectrum_key = band + ":" + std::to_string(channel) + ":" + propagation;
        Ptr<MultiModelSpectrumChannel> spectrum_channel = LookupOrCreateSpectrumChannel(
            spectrum_key,
            propagation);

        for (const auto& endpoint : network.members) {
            const RuntimeRadio& radio = ResolveRadio(endpoint);
            ValidateRadioCompatibility(first_radio, radio, endpoint);

            SpectrumWifiPhyHelper phy;
            phy.SetChannel(spectrum_channel);
            ApplyPhyAttributes(phy, radio);

            Ptr<Node> node = ResolveNode(endpoint.node_id);
            NodeContainer node_container;
            node_container.Add(node);
            NetDeviceContainer devices = wifi.Install(phy, mac, node_container);

            if (devices.GetN() != 1) {
                throw std::runtime_error("failed to create wifi device for endpoint " +
                                         RadioKey(endpoint.node_id, endpoint.radio_id));
            }

            const std::string key = RadioKey(endpoint.node_id, endpoint.radio_id);
            m_radio_devices.emplace(key, devices.Get(0));
            AttachTap(endpoint, devices.Get(0));
            EmitL2Ready(endpoint, network.id, band, channel);
        }
    }

    void ValidateRadioCompatibility(
        const RuntimeRadio& expected,
        const RuntimeRadio& actual,
        const RuntimeEndpoint& endpoint) const {
        const auto expected_band = NormalizeLower(expected.band.value_or("5ghz"));
        const auto actual_band = NormalizeLower(actual.band.value_or("5ghz"));
        if (expected_band != actual_band) {
            throw std::runtime_error(
                "radio band mismatch in network for endpoint " +
                RadioKey(endpoint.node_id, endpoint.radio_id));
        }

        if (expected.channel.value_or(0) != actual.channel.value_or(0)) {
            throw std::runtime_error(
                "radio channel mismatch in network for endpoint " +
                RadioKey(endpoint.node_id, endpoint.radio_id));
        }

        const auto expected_backend = NormalizeLower(expected.phy_backend.value_or("spectrum"));
        const auto actual_backend = NormalizeLower(actual.phy_backend.value_or("spectrum"));
        if (expected_backend != actual_backend) {
            throw std::runtime_error(
                "radio phy backend mismatch in network for endpoint " +
                RadioKey(endpoint.node_id, endpoint.radio_id));
        }
    }

    void ConfigureYansPropagation(
        YansWifiChannelHelper& helper,
        const std::string& propagation) const {
        if (propagation == "friis") {
            helper.AddPropagationLoss("ns3::FriisPropagationLossModel");
            return;
        }
        if (propagation == "nakagami") {
            helper.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
            return;
        }

        helper.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
    }

    Ptr<MultiModelSpectrumChannel> LookupOrCreateSpectrumChannel(
        const std::string& key,
        const std::string& propagation) {
        const auto it = m_spectrum_channels.find(key);
        if (it != m_spectrum_channels.end()) {
            return it->second;
        }

        Ptr<MultiModelSpectrumChannel> channel = CreateObject<MultiModelSpectrumChannel>();
        if (propagation == "friis") {
            channel->AddPropagationLossModel(CreateObject<FriisPropagationLossModel>());
        } else if (propagation == "nakagami") {
            channel->AddPropagationLossModel(CreateObject<NakagamiPropagationLossModel>());
        } else {
            channel->AddPropagationLossModel(CreateObject<LogDistancePropagationLossModel>());
        }
        channel->SetPropagationDelayModel(CreateObject<ConstantSpeedPropagationDelayModel>());

        m_spectrum_channels.emplace(key, channel);
        return channel;
    }

    void ApplyPhyAttributes(SpectrumWifiPhyHelper& phy, const RuntimeRadio& radio) const {
        if (radio.channel_width_mhz.has_value()) {
            phy.Set("ChannelWidth", UintegerValue(*radio.channel_width_mhz));
        }
        if (radio.tx_power_dbm.has_value()) {
            phy.Set("TxPowerStart", DoubleValue(*radio.tx_power_dbm));
            phy.Set("TxPowerEnd", DoubleValue(*radio.tx_power_dbm));
        }
        if (radio.rx_noise_figure_db.has_value()) {
            phy.Set("RxNoiseFigure", DoubleValue(*radio.rx_noise_figure_db));
        }
    }

    void ApplyPhyAttributes(YansWifiPhyHelper& phy, const RuntimeRadio& radio) const {
        if (radio.channel_width_mhz.has_value()) {
            phy.Set("ChannelWidth", UintegerValue(*radio.channel_width_mhz));
        }
        if (radio.tx_power_dbm.has_value()) {
            phy.Set("TxPowerStart", DoubleValue(*radio.tx_power_dbm));
            phy.Set("TxPowerEnd", DoubleValue(*radio.tx_power_dbm));
        }
        if (radio.rx_noise_figure_db.has_value()) {
            phy.Set("RxNoiseFigure", DoubleValue(*radio.rx_noise_figure_db));
        }
    }

    void AttachTap(const RuntimeEndpoint& endpoint, Ptr<NetDevice> device) const {
        TapBridgeHelper tap;
        tap.SetAttribute("Mode", StringValue("UseLocal"));
        tap.SetAttribute("DeviceName", StringValue(endpoint.tap_if));
        tap.Install(ResolveNode(endpoint.node_id), device);
    }

    void EmitL2Ready(
        const RuntimeEndpoint& endpoint,
        const std::string& network_id,
        const std::string& band,
        uint32_t channel) const {
        Simulator::Schedule(MilliSeconds(50), [endpoint, network_id, band, channel]() {
            json event{
                {"type", "l2"},
                {"event", "l2_ready"},
                {"node", endpoint.node_id},
                {"radio", endpoint.radio_id},
                {"network", network_id},
                {"band", band},
                {"channel", channel},
            };
            std::cout << event.dump() << std::endl;
        });
    }

    void ScheduleMobilityTelemetry() {
        Simulator::Schedule(Seconds(0.5), [this]() { EmitMobilityTelemetry(); });
    }

    void EmitMobilityTelemetry() {
        for (const auto& [node_id, node] : m_nodes) {
            Ptr<MobilityModel> mobility = node->GetObject<MobilityModel>();
            if (!mobility) {
                continue;
            }
            Vector pos = mobility->GetPosition();
            json event{
                {"type", "mobility"},
                {"node", node_id},
                {"x_m", pos.x},
                {"y_m", pos.y},
                {"z_m", pos.z},
            };
            std::cout << event.dump() << std::endl;
        }

        Simulator::Schedule(Seconds(1.0), [this]() { EmitMobilityTelemetry(); });
    }

    void ScheduleRealtimeTelemetry() {
        Simulator::Schedule(Seconds(1.0), [this]() { EmitRealtimeTelemetry(); });
    }

    void EmitRealtimeTelemetry() {
        const auto wall_now = std::chrono::steady_clock::now();
        const uint64_t wall_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(wall_now - m_wall_start)
                .count();
        const uint64_t sim_ms = Simulator::Now().GetMilliSeconds();
        const int64_t lag_ms = static_cast<int64_t>(wall_ms) - static_cast<int64_t>(sim_ms);

        std::cout << BuildRealtimeEvent(sim_ms, wall_ms, lag_ms).dump() << std::endl;

        if (lag_ms > static_cast<int64_t>(m_cfg.realtime_hard_limit_ms)) {
            m_realtime_hard_limit_exceeded = true;
            json error_event{
                {"type", "realtime"},
                {"event", "hard_limit_exceeded"},
                {"sim_ms", sim_ms},
                {"wall_ms", wall_ms},
                {"lag_ms", lag_ms},
                {"hard_limit_ms", m_cfg.realtime_hard_limit_ms},
            };
            std::cout << error_event.dump() << std::endl;
            Simulator::Stop();
            return;
        }

        Simulator::Schedule(Seconds(1.0), [this]() { EmitRealtimeTelemetry(); });
    }

    Ptr<Node> ResolveNode(const std::string& node_id) const {
        const auto it = m_nodes.find(node_id);
        if (it == m_nodes.end()) {
            throw std::runtime_error("unknown node id: " + node_id);
        }
        return it->second;
    }

    const RuntimeRadio& ResolveRadio(const RuntimeEndpoint& endpoint) const {
        const auto it = m_radios.find(RadioKey(endpoint.node_id, endpoint.radio_id));
        if (it == m_radios.end()) {
            throw std::runtime_error(
                "unknown radio reference: " + RadioKey(endpoint.node_id, endpoint.radio_id));
        }
        return it->second;
    }

    RuntimeConfig m_cfg;
    std::unordered_map<std::string, Ptr<Node>> m_nodes;
    std::unordered_map<std::string, RuntimeRadio> m_radios;
    std::unordered_map<std::string, Ptr<NetDevice>> m_radio_devices;
    std::unordered_map<std::string, Ptr<MultiModelSpectrumChannel>> m_spectrum_channels;
    std::chrono::steady_clock::time_point m_wall_start;
    bool m_realtime_hard_limit_exceeded = false;
};

int Main(int argc, char** argv) {
    std::string config_path;
    uint64_t duration_secs = 0;

    CommandLine cmd;
    cmd.AddValue("config", "Path to ns3 runtime JSON config", config_path);
    cmd.AddValue("duration-secs", "Scenario duration in seconds", duration_secs);
    cmd.Parse(argc, argv);

    if (config_path.empty()) {
        std::cerr << "missing --config argument" << std::endl;
        return 2;
    }

    RuntimeConfig cfg = ParseRuntimeConfig(config_path);
    AvenaNs3Driver driver(std::move(cfg));
    driver.Initialize();

    std::cout << "ns3_ready" << std::endl;
    return driver.Run(duration_secs);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return Main(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "ns3 driver error: " << ex.what() << std::endl;
        return 2;
    }
}

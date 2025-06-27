#include <gtest/gtest.h>
#include "openadp/client.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"

namespace openadp {
namespace test {

class ClientTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test JsonRpcRequest
TEST_F(ClientTest, JsonRpcRequestCreation) {
    client::JsonRpcRequest request("test_method");
    
    EXPECT_EQ(request.method, "test_method");
    EXPECT_EQ(request.id, "1");
    EXPECT_FALSE(request.encrypted);
    EXPECT_TRUE(request.params.is_null());
    
    nlohmann::json dict = request.to_dict();
    EXPECT_EQ(dict["method"], "test_method");
    EXPECT_EQ(dict["id"], "1");
    EXPECT_TRUE(dict["params"].is_null());
}

TEST_F(ClientTest, JsonRpcRequestWithParams) {
    nlohmann::json params;
    params["key1"] = "value1";
    params["key2"] = 42;
    
    client::JsonRpcRequest request("test_method", params);
    
    EXPECT_EQ(request.method, "test_method");
    EXPECT_EQ(request.params, params);
    
    nlohmann::json dict = request.to_dict();
    EXPECT_EQ(dict["params"]["key1"], "value1");
    EXPECT_EQ(dict["params"]["key2"], 42);
}

// Test JsonRpcResponse
TEST_F(ClientTest, JsonRpcResponseSuccess) {
    nlohmann::json response_json;
    response_json["result"] = "success";
    response_json["error"] = nullptr;
    response_json["id"] = "1";
    
    client::JsonRpcResponse response = client::JsonRpcResponse::from_json(response_json);
    
    EXPECT_EQ(response.result, "success");
    EXPECT_TRUE(response.error.is_null());
    EXPECT_EQ(response.id, "1");
    EXPECT_FALSE(response.has_error());
}

TEST_F(ClientTest, JsonRpcResponseError) {
    nlohmann::json response_json;
    response_json["result"] = nullptr;
    response_json["error"] = "Something went wrong";
    response_json["id"] = "1";
    
    client::JsonRpcResponse response = client::JsonRpcResponse::from_json(response_json);
    
    EXPECT_TRUE(response.result.is_null());
    EXPECT_EQ(response.error, "Something went wrong");
    EXPECT_EQ(response.id, "1");
    EXPECT_TRUE(response.has_error());
}

// Test RegisterSecretRequest
TEST_F(ClientTest, RegisterSecretRequest) {
    Identity identity("user123", "device456", "backup789");
    client::RegisterSecretRequest request(identity, "password123", 5, 3600, "secret_data");
    
    EXPECT_EQ(request.identity.uid, "user123");
    EXPECT_EQ(request.identity.did, "device456");
    EXPECT_EQ(request.identity.bid, "backup789");
    EXPECT_EQ(request.password, "password123");
    EXPECT_EQ(request.max_guesses, 5);
    EXPECT_EQ(request.expiration, 3600);
    EXPECT_EQ(request.b, "secret_data");
}

// Test RecoverSecretRequest
TEST_F(ClientTest, RecoverSecretRequest) {
    Identity identity("user123", "device456", "backup789");
    client::RecoverSecretRequest request(identity, "password123", 2);
    
    EXPECT_EQ(request.identity.uid, "user123");
    EXPECT_EQ(request.identity.did, "device456");
    EXPECT_EQ(request.identity.bid, "backup789");
    EXPECT_EQ(request.password, "password123");
    EXPECT_EQ(request.guess_num, 2);
    EXPECT_FALSE(request.encrypted);
}

// Test ServerInfo parsing
TEST_F(ClientTest, ParseServerInfo) {
    nlohmann::json server_json;
    server_json["url"] = "https://example.com";
    
    ServerInfo info = client::parse_server_info(server_json);
    
    EXPECT_EQ(info.url, "https://example.com");
    EXPECT_FALSE(info.public_key.has_value());
}

TEST_F(ClientTest, ParseServerInfoWithPublicKey) {
    nlohmann::json server_json;
    server_json["url"] = "https://example.com";
    server_json["public_key"] = "SGVsbG8gV29ybGQ="; // "Hello World" in base64
    
    ServerInfo info = client::parse_server_info(server_json);
    
    EXPECT_EQ(info.url, "https://example.com");
    EXPECT_TRUE(info.public_key.has_value());
    
    std::string decoded = utils::bytes_to_string(info.public_key.value());
    EXPECT_EQ(decoded, "Hello World");
}

// Test servers response parsing
TEST_F(ClientTest, ParseServersResponse) {
    nlohmann::json response;
    response["servers"] = nlohmann::json::array();
    
    nlohmann::json server1;
    server1["url"] = "https://server1.com";
    response["servers"].push_back(server1);
    
    nlohmann::json server2;
    server2["url"] = "https://server2.com";
    server2["public_key"] = "SGVsbG8="; // "Hello" in base64
    response["servers"].push_back(server2);
    
    std::vector<ServerInfo> servers = client::parse_servers_response(response);
    
    EXPECT_EQ(servers.size(), 2);
    EXPECT_EQ(servers[0].url, "https://server1.com");
    EXPECT_FALSE(servers[0].public_key.has_value());
    EXPECT_EQ(servers[1].url, "https://server2.com");
    EXPECT_TRUE(servers[1].public_key.has_value());
}

TEST_F(ClientTest, ParseServersResponseEmpty) {
    nlohmann::json response;
    response["servers"] = nlohmann::json::array();
    
    std::vector<ServerInfo> servers = client::parse_servers_response(response);
    
    EXPECT_EQ(servers.size(), 0);
}

TEST_F(ClientTest, ParseServersResponseNoServersField) {
    nlohmann::json response;
    response["other_field"] = "value";
    
    std::vector<ServerInfo> servers = client::parse_servers_response(response);
    
    EXPECT_EQ(servers.size(), 0);
}

// Test fallback server info
TEST_F(ClientTest, GetFallbackServerInfo) {
    std::vector<ServerInfo> servers = client::get_fallback_server_info();
    
    EXPECT_GT(servers.size(), 0); // Should have at least one fallback server
    
    for (const auto& server : servers) {
        EXPECT_FALSE(server.url.empty());
        EXPECT_TRUE(server.url.substr(0, 8) == "https://");
    }
}

// Test BasicOpenADPClient creation
TEST_F(ClientTest, BasicClientCreation) {
    std::string url = "https://example.com";
    
    EXPECT_NO_THROW(client::BasicOpenADPClient client(url));
    EXPECT_NO_THROW(client::BasicOpenADPClient client(url, 60));
}

TEST_F(ClientTest, BasicClientGetters) {
    std::string url = "https://example.com";
    int timeout = 45;
    
    client::BasicOpenADPClient client(url, timeout);
    
    EXPECT_EQ(client.url(), url);
    EXPECT_EQ(client.timeout(), timeout);
}

// Test EncryptedOpenADPClient creation
TEST_F(ClientTest, EncryptedClientCreation) {
    std::string url = "https://example.com";
    
    // Without public key
    EXPECT_NO_THROW(client::EncryptedOpenADPClient client(url, std::nullopt));
    
    // With public key
    Bytes public_key = utils::random_bytes(32);
    EXPECT_NO_THROW(client::EncryptedOpenADPClient client(url, public_key));
}

TEST_F(ClientTest, EncryptedClientHasPublicKey) {
    std::string url = "https://example.com";
    
    // Without public key
    client::EncryptedOpenADPClient client1(url, std::nullopt);
    EXPECT_FALSE(client1.has_public_key());
    
    // With public key
    Bytes public_key = utils::random_bytes(32);
    client::EncryptedOpenADPClient client2(url, public_key);
    EXPECT_TRUE(client2.has_public_key());
}

TEST_F(ClientTest, EncryptedClientUrl) {
    std::string url = "https://example.com";
    client::EncryptedOpenADPClient client(url, std::nullopt);
    
    EXPECT_EQ(client.url(), url);
}

// Note: Network-dependent tests would require mock servers or integration test setup
// For now, we focus on unit tests that don't require actual network calls

} // namespace test
} // namespace openadp 
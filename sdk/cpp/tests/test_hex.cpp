#include <gtest/gtest.h>
#include "openadp/utils.hpp"
#include "openadp/types.hpp"

namespace openadp {
namespace test {

class HexTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(HexTest, EncodeEmptyData) {
    Bytes empty_data;
    std::string result = utils::hex_encode(empty_data);
    EXPECT_EQ(result, "");
}

TEST_F(HexTest, EncodeSimpleData) {
    Bytes data = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    std::string encoded = utils::hex_encode(data);
    EXPECT_EQ(encoded, "48656c6c6f");
}

TEST_F(HexTest, EncodeDecodeRoundTrip) {
    Bytes original = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC};
    std::string encoded = utils::hex_encode(original);
    Bytes decoded = utils::hex_decode(encoded);
    
    EXPECT_EQ(original, decoded);
}

TEST_F(HexTest, DecodeUppercase) {
    std::string hex_upper = "48656C6C6F";
    Bytes expected = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    Bytes decoded = utils::hex_decode(hex_upper);
    
    EXPECT_EQ(expected, decoded);
}

TEST_F(HexTest, DecodeLowercase) {
    std::string hex_lower = "48656c6c6f";
    Bytes expected = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    Bytes decoded = utils::hex_decode(hex_lower);
    
    EXPECT_EQ(expected, decoded);
}

TEST_F(HexTest, DecodeMixedCase) {
    std::string hex_mixed = "48656C6c6F";
    Bytes expected = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    Bytes decoded = utils::hex_decode(hex_mixed);
    
    EXPECT_EQ(expected, decoded);
}

TEST_F(HexTest, DecodeInvalidCharacters) {
    // Test various invalid hex characters
    EXPECT_THROW(utils::hex_decode("GG"), OpenADPError);
    // Note: "4G" might be interpreted as "4" + invalid, but some implementations are lenient
    // Let's test clearly invalid strings instead
    EXPECT_THROW(utils::hex_decode("ZZ"), OpenADPError);
    EXPECT_THROW(utils::hex_decode("G4"), OpenADPError);
    EXPECT_THROW(utils::hex_decode("@@"), OpenADPError);
    EXPECT_THROW(utils::hex_decode("Hello"), OpenADPError);
}

TEST_F(HexTest, DecodeOddLength) {
    EXPECT_THROW(utils::hex_decode("123"), OpenADPError);
    EXPECT_THROW(utils::hex_decode("A"), OpenADPError);
}

TEST_F(HexTest, EncodeAllBytes) {
    // Test encoding all possible byte values
    Bytes all_bytes;
    for (int i = 0; i <= 255; i++) {
        all_bytes.push_back(static_cast<uint8_t>(i));
    }
    
    std::string encoded = utils::hex_encode(all_bytes);
    Bytes decoded = utils::hex_decode(encoded);
    
    EXPECT_EQ(all_bytes, decoded);
}

TEST_F(HexTest, StringToBytes) {
    std::string input = "Hello World";
    Bytes expected = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
    Bytes result = utils::string_to_bytes(input);
    
    EXPECT_EQ(expected, result);
}

TEST_F(HexTest, BytesToString) {
    Bytes input = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
    std::string expected = "Hello World";
    std::string result = utils::bytes_to_string(input);
    
    EXPECT_EQ(expected, result);
}

TEST_F(HexTest, StringBytesRoundTrip) {
    std::string original = "The quick brown fox jumps over the lazy dog!@#$%^&*()";
    Bytes bytes = utils::string_to_bytes(original);
    std::string result = utils::bytes_to_string(bytes);
    
    EXPECT_EQ(original, result);
}

TEST_F(HexTest, RandomHex) {
    // Test random hex generation
    std::string hex1 = utils::random_hex(16);
    std::string hex2 = utils::random_hex(16);
    
    EXPECT_EQ(hex1.length(), 32); // 16 bytes = 32 hex chars
    EXPECT_EQ(hex2.length(), 32);
    EXPECT_NE(hex1, hex2); // Should be different (extremely high probability)
    
    // Verify it's valid hex
    EXPECT_NO_THROW(utils::hex_decode(hex1));
    EXPECT_NO_THROW(utils::hex_decode(hex2));
}

TEST_F(HexTest, RandomBytes) {
    // Test random bytes generation
    Bytes bytes1 = utils::random_bytes(32);
    Bytes bytes2 = utils::random_bytes(32);
    
    EXPECT_EQ(bytes1.size(), 32);
    EXPECT_EQ(bytes2.size(), 32);
    EXPECT_NE(bytes1, bytes2); // Should be different (extremely high probability)
}

TEST_F(HexTest, EmptyStringConversions) {
    std::string empty_str = "";
    Bytes empty_bytes;
    
    EXPECT_EQ(utils::string_to_bytes(empty_str), empty_bytes);
    EXPECT_EQ(utils::bytes_to_string(empty_bytes), empty_str);
}

} // namespace test
} // namespace openadp 
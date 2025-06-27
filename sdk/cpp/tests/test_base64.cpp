#include <gtest/gtest.h>
#include "openadp/utils.hpp"
#include "openadp/types.hpp"

namespace openadp {
namespace test {

class Base64Test : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(Base64Test, EncodeEmptyString) {
    Bytes empty_data;
    std::string result = utils::base64_encode(empty_data);
    EXPECT_EQ(result, "");
}

TEST_F(Base64Test, EncodeSimpleString) {
    std::string input = "Hello World";
    Bytes data = utils::string_to_bytes(input);
    std::string encoded = utils::base64_encode(data);
    EXPECT_EQ(encoded, "SGVsbG8gV29ybGQ=");
}

TEST_F(Base64Test, EncodeDecodeRoundTrip) {
    std::string original = "The quick brown fox jumps over the lazy dog";
    Bytes original_bytes = utils::string_to_bytes(original);
    
    std::string encoded = utils::base64_encode(original_bytes);
    Bytes decoded = utils::base64_decode(encoded);
    std::string result = utils::bytes_to_string(decoded);
    
    EXPECT_EQ(original, result);
}

TEST_F(Base64Test, EncodeBinaryData) {
    Bytes binary_data = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC};
    std::string encoded = utils::base64_encode(binary_data);
    Bytes decoded = utils::base64_decode(encoded);
    
    EXPECT_EQ(binary_data, decoded);
}

TEST_F(Base64Test, EncodeSpecialCharacters) {
    std::string input = "Hello\n\r\t\0World";
    Bytes data(input.begin(), input.end());
    
    std::string encoded = utils::base64_encode(data);
    Bytes decoded = utils::base64_decode(encoded);
    
    EXPECT_EQ(data, decoded);
}

TEST_F(Base64Test, DecodeInvalidInput) {
    // Test with invalid base64 characters
    EXPECT_THROW(utils::base64_decode("Invalid@#$%"), OpenADPError);
}

TEST_F(Base64Test, DecodePaddingVariations) {
    // Test different padding scenarios
    std::string input1 = "A";
    std::string input2 = "AB";
    std::string input3 = "ABC";
    std::string input4 = "ABCD";
    
    Bytes data1 = utils::string_to_bytes(input1);
    Bytes data2 = utils::string_to_bytes(input2);
    Bytes data3 = utils::string_to_bytes(input3);
    Bytes data4 = utils::string_to_bytes(input4);
    
    std::string encoded1 = utils::base64_encode(data1);
    std::string encoded2 = utils::base64_encode(data2);
    std::string encoded3 = utils::base64_encode(data3);
    std::string encoded4 = utils::base64_encode(data4);
    
    EXPECT_EQ(utils::base64_decode(encoded1), data1);
    EXPECT_EQ(utils::base64_decode(encoded2), data2);
    EXPECT_EQ(utils::base64_decode(encoded3), data3);
    EXPECT_EQ(utils::base64_decode(encoded4), data4);
}

TEST_F(Base64Test, EncodeLargeData) {
    // Test with larger data
    Bytes large_data(10000, 0x42); // 10KB of 'B' characters
    
    std::string encoded = utils::base64_encode(large_data);
    Bytes decoded = utils::base64_decode(encoded);
    
    EXPECT_EQ(large_data, decoded);
}

TEST_F(Base64Test, EncodeRandomData) {
    // Test with random binary data
    Bytes random_data;
    for (int i = 0; i < 256; i++) {
        random_data.push_back(static_cast<uint8_t>(i));
    }
    
    std::string encoded = utils::base64_encode(random_data);
    Bytes decoded = utils::base64_decode(encoded);
    
    EXPECT_EQ(random_data, decoded);
}

} // namespace test
} // namespace openadp 
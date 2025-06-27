// Ed25519 operations
class Ed25519 {
public:
    static Point4D hash_to_point(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin);
    static Point4D scalar_mult(const std::string& scalar_hex, const Point4D& point);
    static Point4D point_add(const Point4D& p1, const Point4D& p2);
    static Bytes compress(const Point4D& point);
    static Point4D decompress(const Bytes& data);
    
    // Static methods for direct access (matching Go/Python/JS APIs)
    static Point4D H(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin);
    static bool is_valid_point(const Point4D& point);
    static std::string unexpand(const Point4D& point);
    static Point4D expand(const std::string& point_2d);
};

// Missing crypto functions to match Go implementation
Point4D H(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin);
Bytes derive_enc_key(const Point4D& point);
bool is_valid_point(const Point4D& point);
Point4D point_mul8(const Point4D& point);
Point4D point_mul(const std::string& scalar_hex, const Point4D& point);
Point4D point_add(const Point4D& p1, const Point4D& p2);
Bytes point_compress(const Point4D& point);
Point4D point_decompress(const Bytes& data);
std::string unexpand(const Point4D& point);
Point4D expand(const std::string& point_2d); 
use openadp_ocrypt::{register, recover};

fn main() {
    println!("Testing Rust SDK...");
    println!("✅ Rust SDK imports work correctly");
    
    // Test that the functions exist by referencing them
    let _ = register;
    let _ = recover;
    println!("✅ register function available: true");
    println!("✅ recover function available: true");
}

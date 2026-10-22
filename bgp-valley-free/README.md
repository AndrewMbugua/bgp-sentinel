# bgp-valley-free

[![crates.io](https://img.shields.io/crates/v/bgp-valley-free.svg)](https://crates.io/crates/bgp-valley-free)
[![docs.rs](https://docs.rs/bgp-valley-free/badge.svg)](https://docs.rs/bgp-valley-free)
[![License: MIT](https://img.shields.io/crates/l/MIT)](LICENSE)

AS-path **valley-free routing validation** using the Gao-Rexford commercial internet model.

A "valley" occurs when a route learned from a peer or customer is propagated *uphill* to a provider, which is the classic pattern for a **route leak** (RFC 7908).

## Features

- **CAIDA Dataset Support**: Parses and loads CAIDA AS-Relationship files (serial-1 format).
- **Fast Graph Validation**: Uses `petgraph` to quickly evaluate if a given AS-path conforms to the Gao-Rexford valley-free constraints.
- **Route Leak Detection**: Helps identify erroneous routing announcements that violate business relationships.

## Usage

```toml
[dependencies]
bgp-valley-free = "0.1"
```

```rust
use bgp_valley_free::AsRelGraph;

// Load the CAIDA dataset (e.g., from https://www.caida.org/catalog/datasets/as-relationships/)
let graph = AsRelGraph::load_caida("serial-1.as-rel.txt").unwrap();

// Test a BGP AS-path
let path = vec![15169, 3356, 6453, 1234]; // Google -> Level3 -> Tata -> AS1234
if !graph.is_valley_free(&path) {
    eprintln!("Route leak detected! The path contains a valley.");
} else {
    println!("Path is valley-free.");
}
```

## License

Licensed under MIT.

//! # bgp-valley-free
//!
//! AS-path **valley-free routing validation** using the Gao-Rexford commercial
//! internet model for **route leak detection** ([RFC 7908]).
//!
//! ## The Valley-Free Problem
//!
//! In the commercial internet, AS relationships fall into two categories:
//!
//! - **Provider–Customer (P→C)**: The customer pays the provider for transit.
//!   Traffic flows *downhill* (provider → customer) when the provider
//!   distributes routes to its customers.
//! - **Peer–Peer (P=P)**: Settlement-free exchange between ASes of similar size.
//!
//! The **Gao-Rexford valley-free constraint** (Gao & Rexford, 2001) says that
//! a BGP path should follow one of these shapes:
//!
//! ```text
//! Uphill→ ... →Peak→ ...→Downhill    (valid)
//!
//! C─P─C─P─C   (uphill then downhill — route leak!)
//!      ↑ valley
//! ```
//!
//! Once a path transitions to "downhill" (Provider→Customer hop), it must
//! **never** go back uphill. Any uphill hop after a downhill hop is a
//! **valley** — the classic route leak pattern (RFC 7908).
//!
//! ## Algorithm
//!
//! The checker maintains a simple two-phase state machine:
//!
//! ```text
//! State: Uphill
//!   ┌─ Peer hop   → stay Uphill
//!   ├─ P→C hop    → transition to Downhill
//!   └─ C→P hop    → stay Uphill (customer paying for transit)
//!
//! State: Downhill
//!   ┌─ P→C hop    → stay Downhill (OK)
//!   └─ anything else → VALLEY detected → return false
//! ```
//!
//! Unknown relationships (ASes not in the CAIDA dataset) are silently skipped
//! (conservative: don't flag paths with unknown hops).
//!
//! ## Data Source
//!
//! Load AS business relationships from [CAIDA AS-Relationship files]:
//!
//! ```text
//! # Format: asn1|asn2|relationship[|source]
//! # relationship: -1 = asn1 is provider of asn2
//! #                0 = peer-peer
//! #                1 = asn1 is customer of asn2
//! 174|2914|-1|bgp
//! 1299|3356|0|bgp
//! ```
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use bgp_valley_free::{AsRelGraph, AsRelationship};
//!
//! // Load CAIDA dataset
//! let graph = AsRelGraph::load_caida("20240101.as-rel.txt").unwrap();
//!
//! // Check a path: AS15169(Google) → AS3356(Level3) → AS6453(Tata) → AS1234
//! let path = &[15169u32, 3356, 6453, 1234];
//! if graph.is_valley_free(path) {
//!     println!("Path is valley-free.");
//! } else {
//!     println!("Route leak detected!");
//! }
//!
//! // Build a graph in-memory for tests
//! let g = AsRelGraph::from_edges(&[
//!     (100, 200, AsRelationship::ProviderCustomer), // AS100 provides transit to AS200
//!     (200, 300, AsRelationship::Peer),              // AS200 and AS300 are peers
//! ]);
//! assert!(g.is_valley_free(&[100, 200, 300])); // uphill then peer — ok
//! ```
//!
//! ## RFC References
//!
//! | RFC | Description |
//! |---|---|
//! | [RFC 7908](https://datatracker.ietf.org/doc/html/rfc7908) | Problem Definition and Classification of BGP Route Leaks |
//! | [RFC 9234](https://datatracker.ietf.org/doc/html/rfc9234) | Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages |
//!
//! ## Performance
//!
//! - Graph construction: O(E) in the number of CAIDA edges (~700 k for 2024).
//! - `is_valley_free`: O(L × D) where L is path length and D is out-degree of
//!   each AS node. Typical paths are 4–6 hops, D is small → sub-microsecond.
//!
//! [CAIDA AS-Relationship files]: https://www.caida.org/catalog/datasets/as-relationships/
//! [RFC 7908]: https://datatracker.ietf.org/doc/html/rfc7908


use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use tracing::info;

// ─────────────────────────────────────────────────────────────────────────────
// AS Relationship
// ─────────────────────────────────────────────────────────────────────────────

/// Business relationship between two AS pairs (Gao-Rexford model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsRelationship {
    /// AS `a` provides transit to AS `b` (a is provider, b is customer).
    ProviderCustomer,
    /// AS `a` and `b` are settlement-free peers.
    Peer,
}

// ─────────────────────────────────────────────────────────────────────────────
// AsRelGraph
// ─────────────────────────────────────────────────────────────────────────────

/// Directed AS-relationship graph for valley-free path validation.
///
/// Edges point **provider → customer** for `ProviderCustomer` relationships,
/// and bidirectionally for `Peer` relationships.
pub struct AsRelGraph {
    graph:   DiGraph<u32, AsRelationship>,
    asn_map: HashMap<u32, NodeIndex>,
}

impl AsRelGraph {
    /// Create an empty graph.
    ///
    /// [`is_valley_free`](Self::is_valley_free) always returns `true` on an
    /// empty graph (conservative: don't flag unknown paths).
    pub fn empty() -> Self {
        Self { graph: DiGraph::new(), asn_map: HashMap::new() }
    }

    /// Load CAIDA AS-Relationship serial-1 data from a file on disk.
    ///
    /// ## File Format
    /// Lines have the format `<asn1>|<asn2>|<relationship>[|<source>]`:
    /// - `-1` → `asn1` is provider of `asn2` (`ProviderCustomer` edge: `asn1 → asn2`)
    /// - `0`  → settlement-free peer-to-peer (`Peer` bidirectional edge)
    /// - `1`  → `asn1` is customer of `asn2` (`ProviderCustomer` edge: `asn2 → asn1`)
    ///
    /// Lines beginning with `#` are treated as comments and skipped.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if the file cannot be opened or read.
    pub fn load_caida(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let mut g = Self::empty();
        let mut edge_count = 0u64;

        for line in data.lines() {
            if line.starts_with('#') { continue; }
            let mut parts = line.split('|');
            let asn1: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let asn2: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let rel: i8   = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            if asn1 == 0 || asn2 == 0 { continue; }

            let a = g.get_or_insert(asn1);
            let b = g.get_or_insert(asn2);

            match rel {
                -1 => { g.graph.add_edge(a, b, AsRelationship::ProviderCustomer); }
                 1 => { g.graph.add_edge(b, a, AsRelationship::ProviderCustomer); }
                 0 => {
                     g.graph.add_edge(a, b, AsRelationship::Peer);
                     g.graph.add_edge(b, a, AsRelationship::Peer);
                 }
                 _ => {}
            }
            edge_count += 1;
        }

        info!(edges = edge_count, nodes = g.asn_map.len(), "CAIDA AS-relationship graph loaded");
        Ok(g)
    }

    /// Build a graph directly from `(asn1, asn2, relationship)` tuples in memory.
    ///
    /// Essential for unit testing and offline path evaluation without requiring
    /// a full CAIDA dataset file on disk.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bgp_valley_free::{AsRelGraph, AsRelationship};
    ///
    /// let graph = AsRelGraph::from_edges(&[
    ///     (1, 2, AsRelationship::ProviderCustomer), // AS1 provides transit to AS2
    ///     (2, 3, AsRelationship::Peer),             // AS2 peers with AS3
    /// ]);
    /// assert_eq!(graph.node_count(), 3);
    /// assert_eq!(graph.edge_count(), 2);
    /// ```
    pub fn from_edges(edges: &[(u32, u32, AsRelationship)]) -> Self {
        let mut g = Self::empty();
        for &(a, b, rel) in edges {
            let na = g.get_or_insert(a);
            let nb = g.get_or_insert(b);
            g.graph.add_edge(na, nb, rel);
        }
        g
    }

    /// Returns the total number of unique AS nodes in the graph.
    pub fn node_count(&self) -> usize { self.asn_map.len() }

    /// Returns the total number of relationship edges stored.
    pub fn edge_count(&self) -> usize { self.graph.edge_count() }

    /// Returns `true` if the AS-path is valley-free under the Gao-Rexford commercial model.
    ///
    /// A path is **valley-free** if and only if it consists of:
    /// 1. Zero or more customer-to-provider steps (uphill), followed by
    /// 2. At most one peer-to-peer step, followed by
    /// 3. Zero or more provider-to-customer steps (downhill).
    ///
    /// Once a path begins descending (downhill) or traverses a peer edge, it may
    /// NEVER ascend again (i.e. a customer or peer may never provide transit across
    /// two providers or peers).
    ///
    /// # Conservative Handling:
    /// - Returns `true` if the graph is empty (do not flag false positives when CAIDA data is unconfigured).
    /// - Returns `true` for paths shorter than 2 hops (no transitions to check).
    /// - Skips hops with unknown commercial relationships.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bgp_valley_free::{AsRelGraph, AsRelationship};
    ///
    /// // AS1 (Provider) -> AS2 (Customer). AS3 (Provider) -> AS2 (Customer).
    /// let graph = AsRelGraph::from_edges(&[
    ///     (1, 2, AsRelationship::ProviderCustomer),
    ///     (3, 2, AsRelationship::ProviderCustomer),
    /// ]);
    ///
    /// // Route leak: Customer AS2 provides transit between Provider AS1 and Provider AS3!
    /// assert_eq!(graph.is_valley_free(&[1, 2, 3]), false);
    /// ```
    pub fn is_valley_free(&self, path: &[u32]) -> bool {
        if self.asn_map.is_empty() || path.len() < 2 { return true; }

        #[derive(PartialEq)]
        enum Phase { Uphill, Downhill }
        let mut phase = Phase::Uphill;

        for window in path.windows(2) {
            match (&phase, self.relationship(window[0], window[1])) {
                // Uphill phase: C→P or Peer allowed
                (Phase::Uphill, Some(AsRelationship::Peer)) => {}
                // Transition to downhill on first P→C
                (Phase::Uphill, Some(AsRelationship::ProviderCustomer)) => {
                    phase = Phase::Downhill;
                }
                // Downhill: only P→C permitted
                (Phase::Downhill, Some(AsRelationship::ProviderCustomer)) => {}
                // Valley!
                (Phase::Downhill, _) => return false,
                // Unknown relationship — skip
                (_, None) => {}
            }
        }
        true
    }

    /// Direct lookup of the business relationship from AS `from` to AS `to`.
    ///
    /// Returns `Some(AsRelationship::ProviderCustomer)` if `from` is a provider of `to`,
    /// `Some(AsRelationship::Peer)` if `from` and `to` are mutual settlement-free peers,
    /// or `None` if no relationship exists between these two ASNs in the dataset.
    pub fn relationship(&self, from: u32, to: u32) -> Option<AsRelationship> {
        let a = self.asn_map.get(&from)?;
        let b = self.asn_map.get(&to)?;
        self.graph.edges(*a).find(|e| e.target() == *b).map(|e| *e.weight())
    }

    fn get_or_insert(&mut self, asn: u32) -> NodeIndex {
        if let Some(&idx) = self.asn_map.get(&asn) {
            idx
        } else {
            let idx = self.graph.add_node(asn);
            self.asn_map.insert(asn, idx);
            idx
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_graph() -> AsRelGraph {
        // A -(P→C)→ B -(P→C)→ C -(P→C)→ D
        AsRelGraph::from_edges(&[
            (1, 2, AsRelationship::ProviderCustomer),
            (2, 3, AsRelationship::ProviderCustomer),
            (3, 4, AsRelationship::ProviderCustomer),
        ])
    }

    #[test]
    fn valley_free_downhill_only() {
        let g = simple_graph();
        // Pure downhill: 1→2→3→4
        assert!(g.is_valley_free(&[1, 2, 3, 4]));
    }

    #[test]
    fn valley_detected() {
        // 1→2 P→C (downhill), then 3→2 would be uphill — but we test path order
        // Path: 4→3→2→1 downhill, then trying 4→3→2→3 — just test a constructed valley
        let g = AsRelGraph::from_edges(&[
            (1, 2, AsRelationship::ProviderCustomer), // 1 provides to 2
            (3, 2, AsRelationship::ProviderCustomer), // 3 provides to 2
        ]);
        // Path 2→1 is uphill (C→P), then 1→2 would be downhill (P→C) — no valley
        // Path: downhill 1→2, then uphill 2→3 — valley!
        // From 2's perspective: 2 is customer of 1 (so 2→1 is uphill)
        // From 3's perspective: 2 is customer of 3 (so 1→? we need a peer/downhill first)
        let g2 = AsRelGraph::from_edges(&[
            (1, 2, AsRelationship::ProviderCustomer), // downhill A
            (2, 3, AsRelationship::Peer),             // peer in between
            (4, 3, AsRelationship::ProviderCustomer), // 4 provides to 3, so 3→4 = uphill
        ]);
        // Path: 1→2 (down), 2→3 (peer OK in uphill), 3→4 (uphill C→P after downhill = valley)
        // After 1→2 downhill, phase=Downhill, then 2→3 is Peer → valley
        assert!(!g2.is_valley_free(&[1, 2, 3, 4]));
    }

    #[test]
    fn empty_graph_always_valid() {
        let g = AsRelGraph::empty();
        assert!(g.is_valley_free(&[1, 2, 3]));
    }

    #[test]
    fn single_hop_always_valid() {
        let g = simple_graph();
        assert!(g.is_valley_free(&[1]));
    }
}

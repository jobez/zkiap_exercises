const std = @import("std");
const crypto = std.crypto;
const Hash = std.crypto.hash.sha2.Sha256;
const Random = std.rand.Random;
const RndGen = std.rand.DefaultPrng;

// For an additional challenge, try implementing a non-interactive ZKP for proof of 3-coloring as well!

// via https://hackmd.io/@gubsheep/Hy57lluOs

// we can get started by yoinking the models in ziglings that give us a basic graph flow

// three colors
// n items
// if two items share an edge, they arent the same color

// so we have

// we can pretend we care about colors, but its really just three distinct things, oui?

const secret_length = 77;

const Color = enum { Red, Blue, Green };

const Edge = struct {
    from: usize, // Index of the from vertex
    to: usize, // Index of the to vertex
};

// Public graph structure
const Graph = struct {
    const Self = @This();

    vertices: std.AutoArrayHashMap(usize, bool),
    edges: []Edge,

    fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.vertices.deinit();
        allocator.free(self.edges);
    }
};

// Generates a graph with a specified number of vertices and edges.
// numVertices: Number of vertices in the graph.
// maxEdgesPerVertex: Maximum number of edges that can be connected to a single vertex.
// rng: Random number generator used for generating the graph.
pub fn genGraph(allocator: std.mem.Allocator, num_vertices: usize, allow_self_loop: bool, rng: *std.rand.Random) !Graph {
    var vertex_map = std.AutoArrayHashMap(usize, bool).init(allocator);

    // Initialize vertices in the vertex map
    for (0..num_vertices) |i| {
        try vertex_map.put(i, true); // Add each vertex index to the map
    }

    // Estimate total number of edges for initial allocation
    var edges = try allocator.alloc(Edge, num_vertices);

    var edge_count: usize = 0; // Counter for the actual number of edges added
    for (0..num_vertices) |from_vertex| {
        var to_vertex: usize = 0;
        while (!allow_self_loop and to_vertex == from_vertex or edgeExists(edges[0..edge_count], from_vertex, to_vertex)) {
            to_vertex = rng.int(u32) % num_vertices; // Select a random vertex to connect
        } // Ensure no self-loops or duplicate edges

        edges[edge_count] = Edge{ .from = from_vertex, .to = to_vertex }; // Add the edge
        edge_count += 1; // Increment edge counter
    }

    // Trim the edges array to the actual number of edges created
    _ = allocator.resize(edges, edge_count);

    return Graph{ .vertices = vertex_map, .edges = edges }; // Return the generated graph
}

// Checks if an edge already exists between two vertices.
// edges: The array of existing edges.
// from: The starting vertex index.
// to: The ending vertex index.
fn edgeExists(edges: []const Edge, from: usize, to: usize) bool {
    for (edges) |edge| {
        if ((edge.from == from and edge.to == to) or (edge.from == to and edge.to == from)) {
            return true; // Edge exists
        }
    }
    return false; // No such edge exists
}

fn colorGraph(graph: Graph) [3]Color {
    // Array to store the assigned color for each node
    var node_colors = [3]Color{ Color.Red, Color.Green, Color.Blue };
    // Check the edges and assign different colors to each connected node
    for (graph.edges) |edge| {
        if (node_colors[edge.from] == node_colors[edge.to]) {
            // If the 'from' and 'to' nodes have the same color, change the 'to' node color
            node_colors[edge.to] = nextColor(node_colors[edge.from]);
        }
    }

    return node_colors;
}

fn nextColor(currentColor: Color) Color {
    return switch (currentColor) {
        Color.Red => Color.Green,
        Color.Green => Color.Blue,
        Color.Blue => Color.Red,
    };
}

// conceptualizing The Shape of The Problem
// 0. understanding The Problem Domain
// no two adject vertices can share the same color

// 1. identifying what needs to be Proven
// in ZKP, the goal is to prove knowledge of a certain fact without revealing the underlying information of the fact
// for 3-coloring, the 'fact' is
// the existence of a valid coloring graph

// 2. determing the constraints
// every zkp is built around certain constraints that must be satisfied
// these constraints are derived from the problem itself.
// in the case of 3-coloring, the constraints are coloring rules
const CommitmentContext = struct {
    const Self = @This();
    commitments: [][Hash.digest_length]u8,
    secrets: [][secret_length]u8, // secrets used per commit, to share in reveal
    fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.commitments);
        allocator.free(self.secrets);
    }
};

const Reveal = struct {
    edge_id: usize,
    secrets: [2][secret_length]u8,
    edge: Edge,
    coloring: [2]Color,
};

fn createCommitment(vertex_id: usize, color: Color, secret: [secret_length]u8) [Hash.digest_length]u8 {
    var hasher = Hash.init(.{});
    hasher.update(std.mem.asBytes(&vertex_id));
    hasher.update(@tagName(color));
    hasher.update(&secret);
    return hasher.finalResult();
}

fn generateCommitments(allocator: *std.mem.Allocator, random: *std.rand.Random, graph: Graph, claim: []Color) !CommitmentContext {
    const vertices_len = graph.vertices.keys().len;
    const commitments = try allocator.alloc([Hash.digest_length]u8, vertices_len);
    var secrets = try allocator.alloc([secret_length]u8, vertices_len); // Array to hold slices

    for (0..vertices_len, claim) |vertex_id, color| {
        secrets[vertex_id] = try generateSecret(random); // Generate a unique secret
        commitments[vertex_id] = createCommitment(vertex_id, color, secrets[vertex_id]);
    }

    return CommitmentContext{
        .commitments = commitments,
        .secrets = secrets,
    };
}

fn createChallenge(commitments: [][Hash.digest_length]u8) [Hash.digest_length]u8 {
    var hasher = Hash.init(.{});
    for (commitments) |commit| {
        hasher.update(commit[0..]);
    }
    return hasher.finalResult();
}

pub fn chooseColorForVertex(random: *std.rand.Random) Color {
    const index = random.int(u32) % @intFromEnum(Color.Green) + 1; // +1 because enums start at 0
    return @as(Color, @enumFromInt(index));
}

pub fn generateSecret(random: *std.rand.Random) ![secret_length]u8 {
    var secret: [secret_length]u8 = undefined;
    for (0..secret_length) |idx| {
        secret[idx] = random.int(u8);
    }
    return secret;
}

fn verifyReveal(reveal: Reveal, graph: Graph, originalCommitments: [][Hash.digest_length]u8) bool {
    // Check if the nodes of the edge exist in the graph
    if (!graph.vertices.contains(reveal.edge.from) or !graph.vertices.contains(reveal.edge.to)) {
        return false;
    }

    // Check if the revealed edge exists in the graph
    if (!edgeExists(graph.edges, reveal.edge.from, reveal.edge.to)) {
        return false;
    }

    // Verify that the colors on either end of the edge are different
    if (reveal.coloring[0] == reveal.coloring[1]) {
        return false;
    }

    // Recreate the commitments for the revealed colors and secrets and compare with original commitments
    const from_vertex_commitment = createCommitment(reveal.edge.from, reveal.coloring[0], reveal.secrets[0]);
    const to_vertex_commitment = createCommitment(reveal.edge.to, reveal.coloring[1], reveal.secrets[1]);

    // Check if the commitments match for the vertices of the revealed edge
    if (std.mem.eql(u8, &from_vertex_commitment, &originalCommitments[reveal.edge.from]) and
        std.mem.eql(u8, &to_vertex_commitment, &originalCommitments[reveal.edge.to]))
    {
        return true;
    } else {
        return false;
    }
}

const testing = std.testing;

test "three color" {
    var allocator = std.testing.allocator;
    var rng = RndGen.init(0);
    var random = rng.random(); // Create a Random interface backed by Xoshiro256

    // Instantiate the graph at compile time
    var graph = try genGraph(allocator, 3, false, &random);
    defer graph.deinit(allocator);

    var claim = colorGraph(graph);

    var commitments = try generateCommitments(&allocator, &random, graph, claim[0..]);

    const challenge = createChallenge(commitments.commitments);
    const edge_idx = std.mem.readInt(u32, challenge[0..4], .little) % graph.edges.len;
    const revealed_edge = graph.edges[edge_idx];

    // Select an edge to reveal based on the challenge

    // Reveal the colors of the selected edge's vertices
    const revealed_colors = [2]Color{ claim[revealed_edge.from], claim[revealed_edge.to] };
    const revealed_secrets: [2][secret_length]u8 = .{
        commitments.secrets[revealed_edge.from],
        commitments.secrets[revealed_edge.to],
    };
    const reveal = Reveal{
        .edge_id = edge_idx,
        .secrets = revealed_secrets,
        .edge = revealed_edge,
        .coloring = revealed_colors,
    };

    defer commitments.deinit(allocator);
    try std.testing.expect(verifyReveal(reveal, graph, commitments.commitments));
}

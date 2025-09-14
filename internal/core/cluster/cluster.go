package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// NodeStatus represents the status of a cluster node
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusInactive NodeStatus = "inactive"
	NodeStatusLeader   NodeStatus = "leader"
	NodeStatusFollower NodeStatus = "follower"
)

// MessageType represents different types of cluster messages
type MessageType string

const (
	MessageTypeHeartbeat     MessageType = "heartbeat"
	MessageTypeElection      MessageType = "election"
	MessageTypeLeaderAnnounce MessageType = "leader_announce"
	MessageTypeDataSync      MessageType = "data_sync"
	MessageTypeHealthCheck   MessageType = "health_check"
)

// Node represents a cluster node
type Node struct {
	ID          string            `json:"id"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Status      NodeStatus        `json:"status"`
	LastSeen    time.Time         `json:"last_seen"`
	Metadata    map[string]string `json:"metadata"`
	HealthScore float64           `json:"health_score"`
	Load        float64           `json:"load"`
	Version     string            `json:"version"`
}

// Message represents a cluster message
type Message struct {
	Type      MessageType            `json:"type"`
	From      string                 `json:"from"`
	To        string                 `json:"to,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// Config holds cluster configuration
type Config struct {
	NodeID              string        `json:"node_id" yaml:"node_id" env:"CLUSTER_NODE_ID"`
	BindAddress         string        `json:"bind_address" yaml:"bind_address" env:"CLUSTER_BIND_ADDRESS" default:"0.0.0.0"`
	BindPort            int           `json:"bind_port" yaml:"bind_port" env:"CLUSTER_BIND_PORT" default:"8080"`
	Seeds               []string      `json:"seeds" yaml:"seeds" env:"CLUSTER_SEEDS"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval" yaml:"heartbeat_interval" env:"CLUSTER_HEARTBEAT_INTERVAL" default:"5s"`
	ElectionTimeout     time.Duration `json:"election_timeout" yaml:"election_timeout" env:"CLUSTER_ELECTION_TIMEOUT" default:"10s"`
	HealthCheckInterval time.Duration `json:"health_check_interval" yaml:"health_check_interval" env:"CLUSTER_HEALTH_CHECK_INTERVAL" default:"30s"`
	MaxRetries          int           `json:"max_retries" yaml:"max_retries" env:"CLUSTER_MAX_RETRIES" default:"3"`
	ReplicationFactor   int           `json:"replication_factor" yaml:"replication_factor" env:"CLUSTER_REPLICATION_FACTOR" default:"3"`
	Enabled             bool          `json:"enabled" yaml:"enabled" env:"CLUSTER_ENABLED" default:"false"`
}

// Cluster represents a cluster manager
type Cluster struct {
	config       Config
	currentNode  *Node
	nodes        map[string]*Node
	leaderID     string
	isLeader     bool
	mu           sync.RWMutex
	connections  map[string]*websocket.Conn
	connMu       sync.RWMutex
	messageChan  chan Message
	stopChan     chan struct{}
	handlers     map[MessageType]MessageHandler
	upgrader     websocket.Upgrader
	electionTerm int64
	voteCount    int
	listeners    []ClusterEventListener
}

// MessageHandler defines a function to handle cluster messages
type MessageHandler func(msg Message) error

// ClusterEventListener defines an interface for cluster event listeners
type ClusterEventListener interface {
	OnNodeJoin(node *Node)
	OnNodeLeave(node *Node)
	OnLeaderChange(oldLeader, newLeader string)
	OnClusterHealthChange(healthyNodes, totalNodes int)
}

// NewCluster creates a new cluster instance
func NewCluster(config Config) *Cluster {
	if config.NodeID == "" {
		config.NodeID = generateNodeID()
	}

	cluster := &Cluster{
		config: config,
		currentNode: &Node{
			ID:          config.NodeID,
			Address:     config.BindAddress,
			Port:        config.BindPort,
			Status:      NodeStatusActive,
			LastSeen:    time.Now(),
			Metadata:    make(map[string]string),
			HealthScore: 1.0,
			Load:        0.0,
			Version:     "1.0.0",
		},
		nodes:       make(map[string]*Node),
		connections: make(map[string]*websocket.Conn),
		messageChan: make(chan Message, 100),
		stopChan:    make(chan struct{}),
		handlers:    make(map[MessageType]MessageHandler),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for cluster communication
			},
		},
		listeners: make([]ClusterEventListener, 0),
	}

	// Register default message handlers
	cluster.RegisterHandler(MessageTypeHeartbeat, cluster.handleHeartbeat)
	cluster.RegisterHandler(MessageTypeElection, cluster.handleElection)
	cluster.RegisterHandler(MessageTypeLeaderAnnounce, cluster.handleLeaderAnnounce)
	cluster.RegisterHandler(MessageTypeHealthCheck, cluster.handleHealthCheck)

	return cluster
}

// Start starts the cluster
func (c *Cluster) Start() error {
	if !c.config.Enabled {
		return nil
	}

	// Start HTTP server for cluster communication
	go c.startServer()

	// Start message processing
	go c.processMessages()

	// Start periodic tasks
	go c.startHeartbeat()
	go c.startHealthCheck()

	// Connect to seed nodes
	go c.connectToSeeds()

	// Start leader election if no leader exists
	go c.startLeaderElection()

	return nil
}

// Stop stops the cluster
func (c *Cluster) Stop() error {
	close(c.stopChan)

	// Close all connections
	c.connMu.Lock()
	for _, conn := range c.connections {
		conn.Close()
	}
	c.connMu.Unlock()

	return nil
}

// RegisterHandler registers a message handler
func (c *Cluster) RegisterHandler(msgType MessageType, handler MessageHandler) {
	c.handlers[msgType] = handler
}

// AddListener adds a cluster event listener
func (c *Cluster) AddListener(listener ClusterEventListener) {
	c.listeners = append(c.listeners, listener)
}

// GetNodes returns all cluster nodes
func (c *Cluster) GetNodes() map[string]*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nodes := make(map[string]*Node)
	for id, node := range c.nodes {
		nodes[id] = node
	}
	return nodes
}

// GetLeader returns the current leader node
func (c *Cluster) GetLeader() *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.leaderID == "" {
		return nil
	}
	return c.nodes[c.leaderID]
}

// IsLeader returns true if current node is the leader
func (c *Cluster) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader
}

// BroadcastMessage broadcasts a message to all nodes
func (c *Cluster) BroadcastMessage(msgType MessageType, data map[string]interface{}) error {
	msg := Message{
		Type:      msgType,
		From:      c.currentNode.ID,
		Timestamp: time.Now(),
		Data:      data,
	}

	c.connMu.RLock()
	defer c.connMu.RUnlock()

	for nodeID, conn := range c.connections {
		if nodeID != c.currentNode.ID {
			go func(conn *websocket.Conn, msg Message) {
				if err := conn.WriteJSON(msg); err != nil {
					log.Printf("Failed to send message to node %s: %v", nodeID, err)
				}
			}(conn, msg)
		}
	}

	return nil
}

// SendMessage sends a message to a specific node
func (c *Cluster) SendMessage(nodeID string, msgType MessageType, data map[string]interface{}) error {
	c.connMu.RLock()
	conn, exists := c.connections[nodeID]
	c.connMu.RUnlock()

	if !exists {
		return fmt.Errorf("no connection to node %s", nodeID)
	}

	msg := Message{
		Type:      msgType,
		From:      c.currentNode.ID,
		To:        nodeID,
		Timestamp: time.Now(),
		Data:      data,
	}

	return conn.WriteJSON(msg)
}

// startServer starts the HTTP server for cluster communication
func (c *Cluster) startServer() {
	http.HandleFunc("/cluster/ws", c.handleWebSocket)
	http.HandleFunc("/cluster/health", c.handleHealthEndpoint)
	http.HandleFunc("/cluster/status", c.handleStatusEndpoint)

	addr := fmt.Sprintf("%s:%d", c.config.BindAddress, c.config.BindPort)
	log.Printf("Starting cluster server on %s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Cluster server error: %v", err)
	}
}

// handleWebSocket handles WebSocket connections from other nodes
func (c *Cluster) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := c.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Read node ID from query parameter
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		log.Printf("Missing node_id in WebSocket connection")
		return
	}

	// Store connection
	c.connMu.Lock()
	c.connections[nodeID] = conn
	c.connMu.Unlock()

	// Handle messages
	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("Error reading message from node %s: %v", nodeID, err)
			break
		}

		// Process message
		select {
		case c.messageChan <- msg:
		default:
			log.Printf("Message channel full, dropping message from %s", nodeID)
		}
	}

	// Clean up connection
	c.connMu.Lock()
	delete(c.connections, nodeID)
	c.connMu.Unlock()
}

// processMessages processes incoming cluster messages
func (c *Cluster) processMessages() {
	for {
		select {
		case msg := <-c.messageChan:
			if handler, exists := c.handlers[msg.Type]; exists {
				if err := handler(msg); err != nil {
					log.Printf("Error handling message type %s: %v", msg.Type, err)
				}
			} else {
				log.Printf("No handler for message type %s", msg.Type)
			}
		case <-c.stopChan:
			return
		}
	}
}

// startHeartbeat starts sending periodic heartbeats
func (c *Cluster) startHeartbeat() {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.sendHeartbeat()
		case <-c.stopChan:
			return
		}
	}
}

// sendHeartbeat sends heartbeat to all nodes
func (c *Cluster) sendHeartbeat() {
	data := map[string]interface{}{
		"node_id":      c.currentNode.ID,
		"status":       c.currentNode.Status,
		"health_score": c.currentNode.HealthScore,
		"load":         c.currentNode.Load,
		"timestamp":    time.Now(),
	}

	c.BroadcastMessage(MessageTypeHeartbeat, data)
}

// handleHeartbeat handles heartbeat messages
func (c *Cluster) handleHeartbeat(msg Message) error {
	nodeID := msg.From

	c.mu.Lock()
	defer c.mu.Unlock()

	node, exists := c.nodes[nodeID]
	if !exists {
		// New node joined
		node = &Node{
			ID:       nodeID,
			Status:   NodeStatusActive,
			LastSeen: time.Now(),
			Metadata: make(map[string]string),
		}
		c.nodes[nodeID] = node

		// Notify listeners
		for _, listener := range c.listeners {
			go listener.OnNodeJoin(node)
		}
	}

	// Update node information
	node.LastSeen = time.Now()
	if healthScore, ok := msg.Data["health_score"].(float64); ok {
		node.HealthScore = healthScore
	}
	if load, ok := msg.Data["load"].(float64); ok {
		node.Load = load
	}

	return nil
}

// startLeaderElection starts the leader election process
func (c *Cluster) startLeaderElection() {
	ticker := time.NewTicker(c.config.ElectionTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if c.shouldStartElection() {
				c.startElection()
			}
		case <-c.stopChan:
			return
		}
	}
}

// shouldStartElection determines if an election should be started
func (c *Cluster) shouldStartElection() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Start election if no leader or leader is inactive
	if c.leaderID == "" {
		return true
	}

	leader, exists := c.nodes[c.leaderID]
	if !exists {
		return true
	}

	// Check if leader is still alive
	return time.Since(leader.LastSeen) > c.config.ElectionTimeout
}

// startElection starts a new leader election
func (c *Cluster) startElection() {
	c.mu.Lock()
	c.electionTerm++
	c.voteCount = 1 // Vote for self
	c.mu.Unlock()

	data := map[string]interface{}{
		"candidate_id": c.currentNode.ID,
		"term":         c.electionTerm,
		"health_score": c.currentNode.HealthScore,
	}

	c.BroadcastMessage(MessageTypeElection, data)

	// Wait for votes
	time.AfterFunc(c.config.ElectionTimeout/2, func() {
		c.checkElectionResult()
	})
}

// handleElection handles election messages
func (c *Cluster) handleElection(msg Message) error {
	candidateID := msg.Data["candidate_id"].(string)
	term := int64(msg.Data["term"].(float64))
	healthScore := msg.Data["health_score"].(float64)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Vote for candidate if they have better health score or higher term
	if term > c.electionTerm || (term == c.electionTerm && healthScore > c.currentNode.HealthScore) {
		// Send vote
		voteData := map[string]interface{}{
			"voter_id":     c.currentNode.ID,
			"candidate_id": candidateID,
			"term":         term,
		}

		c.SendMessage(candidateID, MessageTypeElection, voteData)
	}

	return nil
}

// checkElectionResult checks if current node won the election
func (c *Cluster) checkElectionResult() {
	c.mu.Lock()
	defer c.mu.Unlock()

	totalNodes := len(c.nodes) + 1 // Include self
	majority := totalNodes/2 + 1

	if c.voteCount >= majority {
		// Won election, become leader
		c.becomeLeader()
	}
}

// becomeLeader makes current node the leader
func (c *Cluster) becomeLeader() {
	oldLeader := c.leaderID
	c.leaderID = c.currentNode.ID
	c.isLeader = true
	c.currentNode.Status = NodeStatusLeader

	// Announce leadership
	data := map[string]interface{}{
		"leader_id": c.currentNode.ID,
		"term":      c.electionTerm,
	}
	c.BroadcastMessage(MessageTypeLeaderAnnounce, data)

	// Notify listeners
	for _, listener := range c.listeners {
		go listener.OnLeaderChange(oldLeader, c.currentNode.ID)
	}

	log.Printf("Node %s became leader", c.currentNode.ID)
}

// handleLeaderAnnounce handles leader announcement messages
func (c *Cluster) handleLeaderAnnounce(msg Message) error {
	leaderID := msg.Data["leader_id"].(string)
	term := int64(msg.Data["term"].(float64))

	c.mu.Lock()
	defer c.mu.Unlock()

	if term >= c.electionTerm {
		oldLeader := c.leaderID
		c.leaderID = leaderID
		c.isLeader = (leaderID == c.currentNode.ID)
		c.electionTerm = term

		if !c.isLeader {
			c.currentNode.Status = NodeStatusFollower
		}

		// Notify listeners
		if oldLeader != leaderID {
			for _, listener := range c.listeners {
				go listener.OnLeaderChange(oldLeader, leaderID)
			}
		}
	}

	return nil
}

// startHealthCheck starts periodic health checks
func (c *Cluster) startHealthCheck() {
	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performHealthCheck()
		case <-c.stopChan:
			return
		}
	}
}

// performHealthCheck performs health check on all nodes
func (c *Cluster) performHealthCheck() {
	c.mu.Lock()
	nodes := make([]*Node, 0, len(c.nodes))
	for _, node := range c.nodes {
		nodes = append(nodes, node)
	}
	c.mu.Unlock()

	healthyCount := 0
	for _, node := range nodes {
		if time.Since(node.LastSeen) <= c.config.HealthCheckInterval*2 {
			healthyCount++
		} else {
			// Remove inactive node
			c.mu.Lock()
			delete(c.nodes, node.ID)
			c.mu.Unlock()

			// Notify listeners
			for _, listener := range c.listeners {
				go listener.OnNodeLeave(node)
			}
		}
	}

	// Notify listeners about cluster health
	for _, listener := range c.listeners {
		go listener.OnClusterHealthChange(healthyCount, len(nodes))
	}
}

// handleHealthCheck handles health check messages
func (c *Cluster) handleHealthCheck(msg Message) error {
	// Respond with current node status
	responseData := map[string]interface{}{
		"node_id":      c.currentNode.ID,
		"status":       c.currentNode.Status,
		"health_score": c.currentNode.HealthScore,
		"load":         c.currentNode.Load,
		"timestamp":    time.Now(),
	}

	return c.SendMessage(msg.From, MessageTypeHealthCheck, responseData)
}

// connectToSeeds connects to seed nodes
func (c *Cluster) connectToSeeds() {
	for _, seed := range c.config.Seeds {
		go c.connectToNode(seed)
	}
}

// connectToNode connects to a specific node
func (c *Cluster) connectToNode(address string) {
	url := fmt.Sprintf("ws://%s/cluster/ws?node_id=%s", address, c.currentNode.ID)

	for {
		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", address, err)
			time.Sleep(time.Second * 5)
			continue
		}

		// Store connection
		c.connMu.Lock()
		c.connections[address] = conn
		c.connMu.Unlock()

		// Handle messages from this connection
		for {
			var msg Message
			if err := conn.ReadJSON(&msg); err != nil {
				log.Printf("Error reading from %s: %v", address, err)
				break
			}

			select {
			case c.messageChan <- msg:
			default:
				log.Printf("Message channel full, dropping message")
			}
		}

		// Clean up and retry
		c.connMu.Lock()
		delete(c.connections, address)
		c.connMu.Unlock()
		conn.Close()

		time.Sleep(time.Second * 5)
	}
}

// handleHealthEndpoint handles HTTP health check endpoint
func (c *Cluster) handleHealthEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"status":    "healthy",
		"node_id":   c.currentNode.ID,
		"is_leader": c.IsLeader(),
		"timestamp": time.Now(),
	}

	json.NewEncoder(w).Encode(health)
}

// handleStatusEndpoint handles HTTP status endpoint
func (c *Cluster) handleStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"current_node": c.currentNode,
		"leader_id":    c.leaderID,
		"is_leader":    c.isLeader,
		"nodes":        c.GetNodes(),
		"connections":  len(c.connections),
	}

	json.NewEncoder(w).Encode(status)
}

// generateNodeID generates a unique node ID
func generateNodeID() string {
	return fmt.Sprintf("node-%d", time.Now().UnixNano())
}

// GetClusterStats returns cluster statistics
func (c *Cluster) GetClusterStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	healthyNodes := 0
	for _, node := range c.nodes {
		if time.Since(node.LastSeen) <= c.config.HealthCheckInterval*2 {
			healthyNodes++
		}
	}

	return map[string]interface{}{
		"total_nodes":     len(c.nodes) + 1, // Include self
		"healthy_nodes":   healthyNodes + 1, // Include self
		"leader_id":       c.leaderID,
		"is_leader":       c.isLeader,
		"current_node_id": c.currentNode.ID,
		"connections":     len(c.connections),
		"election_term":   c.electionTerm,
	}
}
// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Lexe: tests for the fork's [`NetworkGraph`] additions: change tracking, setting channels and
//! node announcements as received from a trusted source, and writing graphs with only what routing
//! needs.

use crate::ln::msgs::{BaseMessageHandler, RoutingMessageHandler, SocketAddress, MAX_VALUE_MSAT};
use crate::routing::gossip::tests::{
	create_gossip_sync, create_network_graph, get_channel_script, get_signed_channel_announcement,
	get_signed_channel_update, get_signed_node_announcement,
};
use crate::routing::gossip::{
	ChannelInfo, ChannelUpdateInfo, GraphChanges, NetworkGraph, NodeAlias, NodeAnnouncementDetails,
	NodeAnnouncementInfo, NodeId, NodeInfo, P2PGossipSync, RoutingFees,
	STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS,
};
use crate::routing::utxo::{UtxoFuture, UtxoResult};
use crate::types::features::{ChannelFeatures, NodeFeatures};
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, Writeable};
use crate::util::test_utils;
use crate::util::wakers::Notifier;

use bitcoin::amount::Amount;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::network::Network;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::TxOut;

use crate::prelude::*;
use crate::sync::Arc;
use core::sync::atomic::Ordering;

fn create_tracked_network_graph() -> NetworkGraph<Arc<test_utils::TestLogger>> {
	let mut network_graph = create_network_graph();
	network_graph.enable_change_tracking();
	network_graph
}

fn get_node_id(secp_ctx: &Secp256k1<All>, privkey: &SecretKey) -> NodeId {
	NodeId::from_pubkey(&PublicKey::from_secret_key(secp_ctx, privkey))
}

/// Returns `count` node keys and their ids.
fn get_nodes(secp_ctx: &Secp256k1<All>, count: u8) -> (Vec<PublicKey>, Vec<NodeId>) {
	let pubkeys: Vec<PublicKey> = (1..=count)
		.map(|i| PublicKey::from_secret_key(secp_ctx, &SecretKey::from_slice(&[i; 32]).unwrap()))
		.collect();
	let node_ids = pubkeys.iter().map(NodeId::from_pubkey).collect();
	(pubkeys, node_ids)
}

/// Asserts that exactly `channels` and `nodes` changed since the last drain.
#[track_caller]
fn assert_changes<L: Logger>(network_graph: &NetworkGraph<L>, channels: &[u64], nodes: &[NodeId]) {
	let changes = network_graph.drain_changes();
	assert_eq!(changes.channels, channels.iter().copied().collect::<HashSet<_>>());
	assert_eq!(changes.nodes, nodes.iter().copied().collect::<HashSet<_>>());
}

#[test]
fn change_tracking_disabled_by_default() {
	let network_graph = create_network_graph();
	let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();

	let announcement =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
	let update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
	gossip_sync.handle_channel_update(None, &update).unwrap();
	let announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
	gossip_sync.handle_node_announcement(None, &announcement).unwrap();
	network_graph.channel_failed_permanent(update.contents.short_channel_id);
	assert!(network_graph.read_only().channels().is_empty());

	assert!(network_graph.changes.is_none());
	assert_eq!(network_graph.drain_changes(), GraphChanges::default());

	// Nor is it persisted.
	let mut network_graph = create_network_graph();
	network_graph.enable_change_tracking();
	let logger = Arc::new(test_utils::TestLogger::new());
	let read_graph = NetworkGraph::read(&mut &network_graph.encode()[..], logger).unwrap();
	assert!(read_graph.changes.is_none());
}

#[test]
fn change_tracking_channel_announcements() {
	let network_graph = create_tracked_network_graph();
	let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
	let no_utxo_lookup: Option<&test_utils::TestChainSource> = None;
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let node_3_privkey = &SecretKey::from_slice(&[40; 32]).unwrap();
	let node_1 = get_node_id(&secp_ctx, node_1_privkey);
	let node_2 = get_node_id(&secp_ctx, node_2_privkey);
	let node_3 = get_node_id(&secp_ctx, node_3_privkey);

	// Signed, as received from a peer.
	let announcement_0 =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement_0).unwrap();
	assert_changes(&network_graph, &[0], &[node_1, node_2]);

	// Duplicate and rejected announcements record nothing.
	gossip_sync.handle_channel_announcement(None, &announcement_0).unwrap_err();
	let mut invalid_sig = announcement_0.clone();
	invalid_sig.contents.short_channel_id = 1;
	gossip_sync.handle_channel_announcement(None, &invalid_sig).unwrap_err();
	let mut self_channel = invalid_sig.contents.clone();
	self_channel.node_id_2 = self_channel.node_id_1;
	network_graph
		.update_channel_from_unsigned_announcement(&self_channel, &no_utxo_lookup)
		.unwrap_err();
	assert_changes(&network_graph, &[], &[]);

	// Signed, without a UTXO lookup.
	let announcement = get_signed_channel_announcement(
		|announcement| announcement.short_channel_id = 1,
		node_1_privkey,
		node_3_privkey,
		&secp_ctx,
	);
	network_graph.update_channel_from_announcement_no_lookup(&announcement).unwrap();
	assert_changes(&network_graph, &[1], &[node_1, node_3]);

	// Unsigned.
	let mut announcement = announcement.contents;
	announcement.short_channel_id = 2;
	announcement.node_id_1 = node_2;
	network_graph
		.update_channel_from_unsigned_announcement(&announcement, &no_utxo_lookup)
		.unwrap();
	assert_changes(&network_graph, &[2], &[node_2, node_3]);

	// Partial, e.g. from rapid gossip sync, then a duplicate.
	let features = ChannelFeatures::empty();
	network_graph
		.add_channel_from_partial_announcement(3, None, 0, features.clone(), node_3, node_1)
		.unwrap();
	network_graph
		.add_channel_from_partial_announcement(3, None, 0, features, node_3, node_1)
		.unwrap_err();
	assert_changes(&network_graph, &[3], &[node_1, node_3]);

	// A permanently failed channel isn't re-added from gossip.
	network_graph.channel_failed_permanent(0);
	assert_changes(&network_graph, &[0], &[node_1, node_2]);
	gossip_sync.handle_channel_announcement(None, &announcement_0).unwrap_err();
	assert_changes(&network_graph, &[], &[]);
}

#[test]
fn change_tracking_channel_replacement() {
	let secp_ctx = Secp256k1::new();
	let logger = test_utils::TestLogger::new();
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let mut network_graph = NetworkGraph::new(Network::Testnet, &logger);
	network_graph.enable_change_tracking();
	let gossip_sync = P2PGossipSync::new(&network_graph, Some(&chain_source), &logger);
	let script_pubkey = get_channel_script(&secp_ctx);
	let utxo = TxOut { value: Amount::from_sat(1_000_000), script_pubkey };
	*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Sync(Ok(utxo));
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let node_3_privkey = &SecretKey::from_slice(&[40; 32]).unwrap();
	let node_1 = get_node_id(&secp_ctx, node_1_privkey);
	let node_2 = get_node_id(&secp_ctx, node_2_privkey);
	let node_3 = get_node_id(&secp_ctx, node_3_privkey);

	let announcement =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
	assert_changes(&network_graph, &[0], &[node_1, node_2]);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap_err();
	assert_changes(&network_graph, &[], &[]);

	// After a reorg, a different channel with the same SCID replaces it. Both the old and the
	// new endpoints are recorded.
	let announcement =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_3_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
	assert_changes(&network_graph, &[0], &[node_1, node_2, node_3]);
	assert!(network_graph.read_only().node(&node_2).is_none());

	// A channel added without a UTXO lookup is replaced once a lookup gives its capacity.
	let announcement = get_signed_channel_announcement(
		|announcement| announcement.short_channel_id = 1,
		node_2_privkey,
		node_3_privkey,
		&secp_ctx,
	);
	network_graph.update_channel_from_announcement_no_lookup(&announcement).unwrap();
	assert_changes(&network_graph, &[1], &[node_2, node_3]);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
	assert_changes(&network_graph, &[1], &[node_2, node_3]);
	assert_eq!(network_graph.read_only().channel(1).unwrap().capacity_sats, Some(1_000_000));
}

#[test]
fn change_tracking_channel_updates() {
	let network_graph = create_tracked_network_graph();
	let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let announcement =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
	network_graph.drain_changes();

	// Updates in either direction record just the channel, once.
	for timestamp in [100, 101] {
		let update =
			get_signed_channel_update(|u| u.timestamp = timestamp, node_1_privkey, &secp_ctx);
		gossip_sync.handle_channel_update(None, &update).unwrap();
		let update = get_signed_channel_update(
			|u| {
				u.timestamp = timestamp;
				u.channel_flags = 1;
			},
			node_2_privkey,
			&secp_ctx,
		);
		gossip_sync.handle_channel_update(None, &update).unwrap();
	}
	assert_changes(&network_graph, &[0], &[]);
	assert_changes(&network_graph, &[], &[]);

	// Duplicate, older, and rejected updates record nothing, nor does verifying an update.
	let duplicate = get_signed_channel_update(|u| u.timestamp = 101, node_1_privkey, &secp_ctx);
	let older = get_signed_channel_update(|u| u.timestamp = 99, node_1_privkey, &secp_ctx);
	let invalid_sig = get_signed_channel_update(|u| u.timestamp = 102, node_2_privkey, &secp_ctx);
	let unknown_channel = get_signed_channel_update(
		|u| {
			u.timestamp = 102;
			u.short_channel_id = 1;
		},
		node_1_privkey,
		&secp_ctx,
	);
	let invalid_htlc_max = get_signed_channel_update(
		|u| {
			u.timestamp = 102;
			u.htlc_maximum_msat = MAX_VALUE_MSAT + 1;
		},
		node_1_privkey,
		&secp_ctx,
	);
	for update in [duplicate, older, invalid_sig, unknown_channel, invalid_htlc_max] {
		gossip_sync.handle_channel_update(None, &update).unwrap_err();
	}
	let update = get_signed_channel_update(|u| u.timestamp = 102, node_1_privkey, &secp_ctx);
	network_graph.verify_channel_update(&update).unwrap();
	assert_changes(&network_graph, &[], &[]);

	// Unsigned.
	network_graph.update_channel_unsigned(&update.contents).unwrap();
	assert_changes(&network_graph, &[0], &[]);
}

#[test]
fn change_tracking_node_announcements() {
	let network_graph = create_tracked_network_graph();
	let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let node_3_privkey = &SecretKey::from_slice(&[40; 32]).unwrap();
	let node_1 = get_node_id(&secp_ctx, node_1_privkey);
	let node_2 = get_node_id(&secp_ctx, node_2_privkey);
	let announcement =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
	network_graph.drain_changes();

	let announcement = get_signed_node_announcement(|_| {}, node_1_privkey, &secp_ctx);
	gossip_sync.handle_node_announcement(None, &announcement).unwrap();
	assert_changes(&network_graph, &[], &[node_1]);

	// Duplicate, older, and rejected announcements record nothing.
	let older = get_signed_node_announcement(|a| a.timestamp = 99, node_1_privkey, &secp_ctx);
	let mut invalid_sig =
		get_signed_node_announcement(|a| a.timestamp = 101, node_1_privkey, &secp_ctx);
	invalid_sig.signature = announcement.signature;
	let unknown_node = get_signed_node_announcement(|_| {}, node_3_privkey, &secp_ctx);
	for announcement in [announcement, older, invalid_sig, unknown_node] {
		gossip_sync.handle_node_announcement(None, &announcement).unwrap_err();
	}
	assert_changes(&network_graph, &[], &[]);

	// Unsigned.
	let announcement = get_signed_node_announcement(|_| {}, node_2_privkey, &secp_ctx);
	network_graph.update_node_from_unsigned_announcement(&announcement.contents).unwrap();
	assert_changes(&network_graph, &[], &[node_2]);
}

#[test]
fn change_tracking_permanent_failures() {
	let network_graph = create_tracked_network_graph();
	let (pubkeys, nodes) = get_nodes(&Secp256k1::new(), 4);
	for (scid, (a, b)) in [(0, (0, 1)), (1, (0, 2)), (2, (1, 2)), (3, (2, 3))] {
		let features = ChannelFeatures::empty();
		network_graph
			.add_channel_from_partial_announcement(scid, None, 0, features, nodes[a], nodes[b])
			.unwrap();
	}
	network_graph.drain_changes();

	network_graph.channel_failed_permanent(0);
	assert_changes(&network_graph, &[0], &[nodes[0], nodes[1]]);
	network_graph.channel_failed_permanent(0);
	assert_changes(&network_graph, &[], &[]);

	// Removes node 2 and all of its channels, which also removes the other nodes.
	network_graph.node_failed_permanent(&pubkeys[2]);
	assert_changes(&network_graph, &[1, 2, 3], &nodes);
	assert!(network_graph.read_only().channels().is_empty());
	assert!(network_graph.read_only().nodes().is_empty());
	network_graph.node_failed_permanent(&pubkeys[2]);
	assert_changes(&network_graph, &[], &[]);

	// A node without channels, which a deserialized graph may hold, is recorded too.
	let node_counter = network_graph.next_node_counter.fetch_add(1, Ordering::Relaxed) as u32;
	let node = NodeInfo { channels: Vec::new(), announcement_info: None, node_counter };
	network_graph.nodes.write().unwrap().insert(nodes[0], node);
	network_graph.node_failed_permanent(&pubkeys[0]);
	assert_changes(&network_graph, &[], &[nodes[0]]);
	assert!(network_graph.read_only().nodes().is_empty());
}

#[test]
fn change_tracking_stale_channels() {
	let network_graph = create_tracked_network_graph();
	let secp_ctx = Secp256k1::new();
	let privkeys: Vec<SecretKey> =
		(1..=4).map(|i| SecretKey::from_slice(&[i; 32]).unwrap()).collect();
	let nodes: Vec<NodeId> = privkeys.iter().map(|k| get_node_id(&secp_ctx, k)).collect();
	let (stale, fresh): (u32, u32) = (500, 2000);
	// (scid, endpoints, announcement time, update time per direction)
	let channels = [
		(0, (0, 1), fresh, [Some(stale), Some(fresh)]),
		(1, (1, 2), stale, [Some(fresh), Some(fresh)]),
		(2, (2, 3), stale, [Some(fresh), None]),
		(3, (0, 3), fresh, [Some(fresh), Some(fresh)]),
		(4, (1, 3), fresh, [Some(fresh), Some(stale)]),
	];
	for (scid, (a, b), announced_at, update_times) in channels {
		let features = ChannelFeatures::empty();
		network_graph
			.add_channel_from_partial_announcement(
				scid,
				None,
				announced_at.into(),
				features,
				nodes[a],
				nodes[b],
			)
			.unwrap();
		for (direction, timestamp) in update_times.into_iter().enumerate() {
			let Some(timestamp) = timestamp else { continue };
			let update = get_signed_channel_update(
				|u| {
					u.short_channel_id = scid;
					u.timestamp = timestamp;
					u.channel_flags = direction as u8;
				},
				&privkeys[a],
				&secp_ctx,
			);
			network_graph.update_channel_unsigned(&update.contents).unwrap();
		}
	}
	network_graph.drain_changes();

	// Clears the stale direction of channels 0 and 4, and removes channel 2, which misses a
	// direction and was announced long ago. Its endpoints keep other channels.
	let time = u64::from(fresh) + STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS;
	network_graph.remove_stale_channels_and_tracking_with_time(time);
	assert_changes(&network_graph, &[0, 2, 4], &[nodes[2], nodes[3]]);
	let channel_0 = network_graph.read_only().channel(0).unwrap().clone();
	assert!(channel_0.one_to_two.is_none() && channel_0.two_to_one.is_some());
	let channel_4 = network_graph.read_only().channel(4).unwrap().clone();
	assert!(channel_4.one_to_two.is_some() && channel_4.two_to_one.is_none());
	assert!(network_graph.read_only().channel(2).is_none());

	network_graph.remove_stale_channels_and_tracking_with_time(time);
	assert_changes(&network_graph, &[], &[]);
}

#[test]
fn change_tracking_async_utxo_lookup() {
	let secp_ctx = Secp256k1::new();
	let logger = test_utils::TestLogger::new();
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let mut network_graph = NetworkGraph::new(Network::Testnet, &logger);
	network_graph.enable_change_tracking();
	let gossip_sync = P2PGossipSync::new(&network_graph, Some(&chain_source), &logger);
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let node_1 = get_node_id(&secp_ctx, node_1_privkey);
	let node_2 = get_node_id(&secp_ctx, node_2_privkey);
	let future = UtxoFuture::new(Arc::new(Notifier::new()));
	*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Async(future.clone());

	// The announcement, and the update and node announcement received while its UTXO is being
	// looked up, are only applied once the lookup completes.
	let announcement =
		get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx);
	gossip_sync.handle_channel_announcement(None, &announcement).unwrap_err();
	let update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
	gossip_sync.handle_channel_update(None, &update).unwrap_err();
	let node_announcement = get_signed_node_announcement(|_| {}, node_2_privkey, &secp_ctx);
	gossip_sync.handle_node_announcement(None, &node_announcement).unwrap_err();
	assert_changes(&network_graph, &[], &[]);

	let script_pubkey = get_channel_script(&secp_ctx);
	future.resolve(Ok(TxOut { value: Amount::from_sat(1_000_000), script_pubkey }));
	gossip_sync.get_and_clear_pending_msg_events();
	assert_changes(&network_graph, &[0], &[node_1, node_2]);
	let channel = network_graph.read_only().channel(0).unwrap().clone();
	assert!(channel.one_to_two.is_some());
	assert!(network_graph.read_only().node(&node_2).unwrap().announcement_info.is_some());
}

#[test]
#[cfg(feature = "std")]
fn change_tracking_drain_under_read_only_view() {
	// Like a trusted source serving its changes: drain them while holding a `read_only` view, and
	// send the view's state of each changed channel. Once updates stop, the last state sent must
	// be the latest one.
	let network_graph = Arc::new(create_tracked_network_graph());
	let secp_ctx = Secp256k1::new();
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let (node_1, node_2) =
		(get_node_id(&secp_ctx, node_1_privkey), get_node_id(&secp_ctx, node_2_privkey));
	let features = ChannelFeatures::empty();
	network_graph
		.add_channel_from_partial_announcement(0, None, 0, features, node_1, node_2)
		.unwrap();
	let update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx).contents;
	network_graph.drain_changes();

	let writer = {
		let (network_graph, mut update) = (Arc::clone(&network_graph), update.clone());
		std::thread::spawn(move || {
			for timestamp in 1..=1000 {
				update.timestamp = timestamp;
				network_graph.update_channel_unsigned(&update).unwrap();
			}
		})
	};
	let mut last_sent = None;
	loop {
		let finished = writer.is_finished();
		{
			let graph = network_graph.read_only();
			if network_graph.drain_changes().channels.contains(&0) {
				let direction = graph.channel(0).unwrap().one_to_two.as_ref().unwrap();
				last_sent = Some(direction.last_update);
			}
		}
		if finished {
			break;
		}
	}
	writer.join().unwrap();
	assert_eq!(last_sent, Some(1000));
}

/// A channel with both directions, as received from a trusted source.
fn get_channel_info(node_one: NodeId, node_two: NodeId, last_update: u32) -> ChannelInfo {
	let direction = ChannelUpdateInfo {
		htlc_minimum_msat: 1_000,
		htlc_maximum_msat: 100_000_000,
		fees: RoutingFees { base_msat: 1_000, proportional_millionths: 100 },
		last_update,
		cltv_expiry_delta: 144,
		enabled: true,
		last_update_message: None,
	};
	ChannelInfo {
		features: ChannelFeatures::empty(),
		node_one,
		node_two,
		// Placeholders, as `ChannelInfo::read` leaves them.
		node_one_counter: u32::max_value(),
		node_two_counter: u32::max_value(),
		capacity_sats: Some(1_000_000),
		one_to_two: Some(direction.clone()),
		two_to_one: Some(direction),
		announcement_message: None,
		announcement_received_time: 1_000,
	}
}

fn get_node_announcement_info(last_update: u32) -> NodeAnnouncementInfo {
	NodeAnnouncementInfo::Local(NodeAnnouncementDetails {
		features: NodeFeatures::empty(),
		last_update,
		rgb: [1, 2, 3],
		alias: NodeAlias([4; 32]),
		addresses: Vec::new(),
	})
}

/// Returns `node_id`'s channels, sorted, if it exists.
fn get_node_channels<L: Logger>(
	network_graph: &NetworkGraph<L>, node_id: &NodeId,
) -> Option<Vec<u64>> {
	let mut channels = network_graph.read_only().node(node_id)?.channels.clone();
	channels.sort_unstable();
	Some(channels)
}

fn get_node_announcement<L: Logger>(
	network_graph: &NetworkGraph<L>, node_id: &NodeId,
) -> Option<NodeAnnouncementInfo> {
	network_graph.read_only().node(node_id).unwrap().announcement_info.clone()
}

#[test]
fn set_channel_new_scid() {
	let network_graph = create_tracked_network_graph();
	let (_, nodes) = get_nodes(&Secp256k1::new(), 3);

	// Creates both endpoints.
	let info = get_channel_info(nodes[0], nodes[1], 100);
	network_graph.set_channel(7, info.clone());
	assert_changes(&network_graph, &[7], &[nodes[0], nodes[1]]);
	assert_eq!(network_graph.read_only().channel(7), Some(&info));
	assert_eq!(get_node_channels(&network_graph, &nodes[0]), Some(vec![7]));
	assert_eq!(get_node_announcement(&network_graph, &nodes[0]), None);

	// Links to an existing endpoint.
	let info = get_channel_info(nodes[2], nodes[0], 100);
	network_graph.set_channel(8, info.clone());
	assert_changes(&network_graph, &[8], &[nodes[0], nodes[2]]);
	assert_eq!(network_graph.read_only().channel(8), Some(&info));
	assert_eq!(get_node_channels(&network_graph, &nodes[0]), Some(vec![7, 8]));
	assert_eq!(get_node_channels(&network_graph, &nodes[2]), Some(vec![8]));

	// The channels' node counters were set to their endpoints'.
	network_graph.test_node_counter_consistency();
}

#[test]
fn set_channel_same_endpoints() {
	let network_graph = create_tracked_network_graph();
	let (_, nodes) = get_nodes(&Secp256k1::new(), 2);
	network_graph.set_channel(7, get_channel_info(nodes[0], nodes[1], 100));
	let announcement = get_node_announcement_info(100);
	network_graph.set_node_announcement(&nodes[0], Some(announcement.clone()));
	let channel = network_graph.read_only().channel(7).unwrap().clone();
	let counters = (channel.node_one_counter, channel.node_two_counter);
	network_graph.drain_changes();

	// An equal record changes nothing.
	network_graph.set_channel(7, get_channel_info(nodes[0], nodes[1], 100));
	assert_changes(&network_graph, &[], &[]);

	// Replaced in place, even with an older direction, a cleared direction, and a new capacity.
	let mut info = get_channel_info(nodes[0], nodes[1], 50);
	info.two_to_one = None;
	info.capacity_sats = Some(2_000_000);
	network_graph.set_channel(7, info.clone());
	assert_changes(&network_graph, &[7], &[]);
	let channel = network_graph.read_only().channel(7).unwrap().clone();
	assert_eq!(channel, info);
	assert_eq!((channel.node_one_counter, channel.node_two_counter), counters);
	assert_eq!(get_node_channels(&network_graph, &nodes[0]), Some(vec![7]));
	assert_eq!(get_node_announcement(&network_graph, &nodes[0]), Some(announcement));
	network_graph.test_node_counter_consistency();
}

#[test]
fn set_channel_different_endpoints() {
	let network_graph = create_tracked_network_graph();
	let (pubkeys, nodes) = get_nodes(&Secp256k1::new(), 4);
	network_graph.set_channel(7, get_channel_info(nodes[0], nodes[1], 100));
	network_graph.set_channel(8, get_channel_info(nodes[1], nodes[2], 100));
	for node_id in &nodes[..3] {
		network_graph.set_node_announcement(node_id, Some(get_node_announcement_info(100)));
	}
	network_graph.drain_changes();

	// E.g. after a reorg, with older directions than the old channel's. Node 0 is left without
	// channels and removed, while nodes 1 and 2 keep channel 8 and their announcements.
	let info = get_channel_info(nodes[2], nodes[3], 50);
	network_graph.set_channel(7, info.clone());
	assert_changes(&network_graph, &[7], &nodes);
	assert_eq!(network_graph.read_only().channel(7), Some(&info));
	assert_eq!(get_node_channels(&network_graph, &nodes[0]), None);
	assert_eq!(get_node_channels(&network_graph, &nodes[1]), Some(vec![8]));
	assert_eq!(get_node_channels(&network_graph, &nodes[2]), Some(vec![7, 8]));
	assert_eq!(get_node_channels(&network_graph, &nodes[3]), Some(vec![7]));
	assert!(get_node_announcement(&network_graph, &nodes[1]).is_some());
	assert!(get_node_announcement(&network_graph, &nodes[2]).is_some());
	network_graph.test_node_counter_consistency();

	// Swapped endpoints are relinked too. Node 3 has no other channel, so it's recreated
	// without its announcement, as when gossip replaces a channel.
	network_graph.set_node_announcement(&nodes[3], Some(get_node_announcement_info(100)));
	network_graph.drain_changes();
	let info = get_channel_info(nodes[3], nodes[2], 50);
	network_graph.set_channel(7, info.clone());
	assert_changes(&network_graph, &[7], &[nodes[2], nodes[3]]);
	assert_eq!(network_graph.read_only().channel(7), Some(&info));
	assert_eq!(get_node_channels(&network_graph, &nodes[2]), Some(vec![7, 8]));
	assert_eq!(get_node_channels(&network_graph, &nodes[3]), Some(vec![7]));
	assert_eq!(get_node_announcement(&network_graph, &nodes[3]), None);
	network_graph.test_node_counter_consistency();

	// Removals follow the new links.
	network_graph.channel_failed_permanent(7);
	assert_changes(&network_graph, &[7], &[nodes[2], nodes[3]]);
	assert_eq!(get_node_channels(&network_graph, &nodes[2]), Some(vec![8]));
	assert_eq!(get_node_channels(&network_graph, &nodes[3]), None);
	network_graph.node_failed_permanent(&pubkeys[1]);
	assert_changes(&network_graph, &[8], &[nodes[1], nodes[2]]);
	assert!(network_graph.read_only().channels().is_empty());
	assert!(network_graph.read_only().nodes().is_empty());
	network_graph.test_node_counter_consistency();
}

#[test]
fn set_channel_after_permanent_failure() {
	let network_graph = create_tracked_network_graph();
	let (pubkeys, nodes) = get_nodes(&Secp256k1::new(), 3);
	network_graph.set_channel(7, get_channel_info(nodes[0], nodes[1], 100));
	network_graph.set_channel(8, get_channel_info(nodes[1], nodes[2], 100));
	network_graph.channel_failed_permanent(7);
	network_graph.node_failed_permanent(&pubkeys[1]);
	assert!(network_graph.read_only().channels().is_empty());
	network_graph.drain_changes();

	// The trusted source wins over the removal of both the SCID and an endpoint.
	let info = get_channel_info(nodes[0], nodes[1], 100);
	network_graph.set_channel(7, info.clone());
	assert_changes(&network_graph, &[7], &[nodes[0], nodes[1]]);
	assert_eq!(network_graph.read_only().channel(7), Some(&info));
	network_graph.set_channel(7, info);
	assert_changes(&network_graph, &[], &[]);
	network_graph.test_node_counter_consistency();

	// The removals are still tracked, so gossip can't re-add them.
	assert!(network_graph.removed_channels.lock().unwrap().contains_key(&7));
	assert!(network_graph.removed_nodes.lock().unwrap().contains_key(&nodes[1]));
}

#[test]
fn set_channel_with_itself_is_ignored() {
	let network_graph = create_tracked_network_graph();
	let (_, nodes) = get_nodes(&Secp256k1::new(), 2);
	network_graph.set_channel(7, get_channel_info(nodes[0], nodes[0], 100));
	assert_changes(&network_graph, &[], &[]);
	assert!(network_graph.read_only().channels().is_empty());
	assert!(network_graph.read_only().nodes().is_empty());

	// An existing channel is kept.
	let info = get_channel_info(nodes[0], nodes[1], 100);
	network_graph.set_channel(7, info.clone());
	network_graph.drain_changes();
	network_graph.set_channel(7, get_channel_info(nodes[1], nodes[1], 100));
	assert_changes(&network_graph, &[], &[]);
	assert_eq!(network_graph.read_only().channel(7), Some(&info));
}

#[test]
fn set_node_announcement() {
	let network_graph = create_tracked_network_graph();
	let (_, nodes) = get_nodes(&Secp256k1::new(), 3);
	network_graph.set_channel(7, get_channel_info(nodes[0], nodes[1], 100));
	network_graph.drain_changes();

	// Sets an announcement, even an older one, unless it's equal.
	for last_update in [100, 50] {
		let announcement = get_node_announcement_info(last_update);
		network_graph.set_node_announcement(&nodes[0], Some(announcement.clone()));
		assert_eq!(get_node_announcement(&network_graph, &nodes[0]), Some(announcement));
	}
	assert_changes(&network_graph, &[], &[nodes[0]]);
	network_graph.set_node_announcement(&nodes[0], Some(get_node_announcement_info(50)));
	assert_changes(&network_graph, &[], &[]);

	// Clears it.
	network_graph.set_node_announcement(&nodes[0], None);
	assert_changes(&network_graph, &[], &[nodes[0]]);
	assert_eq!(get_node_announcement(&network_graph, &nodes[0]), None);
	network_graph.set_node_announcement(&nodes[0], None);
	assert_changes(&network_graph, &[], &[]);

	// Nodes only exist while they have channels.
	network_graph.set_node_announcement(&nodes[2], Some(get_node_announcement_info(100)));
	assert_changes(&network_graph, &[], &[]);
	assert!(network_graph.read_only().node(&nodes[2]).is_none());
}

/// A graph's channels and nodes with only what routing needs, sorted, with each node's channels
/// sorted. Comparing these ignores node counters, as [`ChannelInfo`]'s equality does.
fn get_routing_view<L: Logger>(
	network_graph: &NetworkGraph<L>,
) -> (Vec<(u64, ChannelInfo)>, Vec<(NodeId, Vec<u64>, Option<NodeAnnouncementInfo>)>) {
	let graph = network_graph.read_only();
	let mut channels: Vec<_> = graph
		.channels()
		.unordered_iter()
		.map(|(scid, channel)| (*scid, channel.to_routing_only()))
		.collect();
	channels.sort_unstable_by_key(|(scid, _)| *scid);
	let mut nodes: Vec<_> = graph
		.nodes()
		.unordered_iter()
		.map(|(node_id, node)| {
			let mut channels = node.channels.clone();
			channels.sort_unstable();
			(*node_id, channels, node.announcement_info.as_ref().map(|a| a.to_routing_only()))
		})
		.collect();
	nodes.sort_unstable_by_key(|(node_id, ..)| *node_id);
	(channels, nodes)
}

#[test]
fn write_for_routing_only_round_trip() {
	let network_graph = create_network_graph();
	let (secp_ctx, gossip_sync) = create_gossip_sync(&network_graph);
	let privkeys: Vec<SecretKey> =
		(1..=3).map(|i| SecretKey::from_slice(&[i; 32]).unwrap()).collect();
	for (scid, (a, b)) in [(1, (0, 1)), (2, (1, 2))] {
		let announcement = get_signed_channel_announcement(
			|announcement| announcement.short_channel_id = scid,
			&privkeys[a],
			&privkeys[b],
			&secp_ctx,
		);
		gossip_sync.handle_channel_announcement(None, &announcement).unwrap();
		for (direction, privkey) in [(0, &privkeys[a]), (1, &privkeys[b])] {
			let update = get_signed_channel_update(
				|u| {
					u.short_channel_id = scid;
					u.channel_flags = direction;
				},
				privkey,
				&secp_ctx,
			);
			gossip_sync.handle_channel_update(None, &update).unwrap();
		}
	}
	// Relayed, with an address, and address data and other data we don't understand.
	let address = SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 9735 };
	let announcement = get_signed_node_announcement(
		|a| {
			a.addresses = vec![address.clone()];
			a.excess_address_data = vec![0xff, 1, 2, 3];
			a.excess_data = vec![4, 5, 6];
		},
		&privkeys[0],
		&secp_ctx,
	);
	gossip_sync.handle_node_announcement(None, &announcement).unwrap();
	let features = announcement.contents.features;
	let announcement = get_signed_node_announcement(
		|a| a.addresses = vec![address.clone()],
		&privkeys[1],
		&secp_ctx,
	);
	network_graph.update_node_from_unsigned_announcement(&announcement.contents).unwrap();
	network_graph.set_last_rapid_gossip_sync_timestamp(42);
	{
		let graph = network_graph.read_only();
		let channel = graph.channel(1).unwrap();
		assert!(channel.announcement_message.is_some());
		assert!(channel.one_to_two.as_ref().unwrap().last_update_message.is_some());
		let node_id = get_node_id(&secp_ctx, &privkeys[0]);
		let announcement_info = graph.node(&node_id).unwrap().announcement_info.as_ref().unwrap();
		assert!(announcement_info.announcement_message().is_some());
		assert_eq!(announcement_info.addresses(), &[address][..]);
	}

	let mut bytes = Vec::new();
	network_graph.write_for_routing_only(&mut bytes).unwrap();
	assert!(bytes.len() < network_graph.encode().len());
	let logger = Arc::new(test_utils::TestLogger::new());
	let read_graph = NetworkGraph::read(&mut &bytes[..], logger).unwrap();

	// All but the messages and addresses are kept.
	assert_eq!(get_routing_view(&read_graph), get_routing_view(&network_graph));
	assert_eq!(read_graph.get_last_rapid_gossip_sync_timestamp(), Some(42));
	let graph = read_graph.read_only();
	let node_id = get_node_id(&secp_ctx, &privkeys[0]);
	let announcement_info = NodeAnnouncementInfo::Local(NodeAnnouncementDetails {
		features,
		last_update: 100,
		rgb: [0; 3],
		alias: NodeAlias([0; 32]),
		addresses: Vec::new(),
	});
	assert_eq!(graph.node(&node_id).unwrap().announcement_info, Some(announcement_info));
	for (_, channel) in graph.channels().unordered_iter() {
		assert_eq!(channel, &channel.to_routing_only());
	}
	for (_, node) in graph.nodes().unordered_iter() {
		if let Some(announcement_info) = node.announcement_info.as_ref() {
			assert!(announcement_info.announcement_message().is_none());
			assert!(announcement_info.addresses().is_empty());
		}
	}
}

#[test]
fn write_for_routing_only_without_messages_or_addresses() {
	// With no messages or addresses to leave out, both writers write the same bytes.
	let network_graph = create_network_graph();
	let secp_ctx = Secp256k1::new();
	let privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let (_, nodes) = get_nodes(&secp_ctx, 3);
	let features = ChannelFeatures::empty();
	network_graph
		.add_channel_from_partial_announcement(
			1,
			Some(1_000_000),
			1_000,
			features.clone(),
			nodes[0],
			nodes[1],
		)
		.unwrap();
	network_graph
		.add_channel_from_partial_announcement(2, None, 1_000, features, nodes[1], nodes[2])
		.unwrap();
	for (scid, direction) in [(1, 0), (1, 1), (2, 1)] {
		let update = get_signed_channel_update(
			|u| {
				u.short_channel_id = scid;
				u.channel_flags = direction;
			},
			privkey,
			&secp_ctx,
		);
		network_graph.update_channel_unsigned(&update.contents).unwrap();
	}
	let announcement = get_signed_node_announcement(|a| a.node_id = nodes[1], privkey, &secp_ctx);
	network_graph.update_node_from_unsigned_announcement(&announcement.contents).unwrap();
	network_graph.set_last_rapid_gossip_sync_timestamp(42);

	let mut bytes = Vec::new();
	network_graph.write_for_routing_only(&mut bytes).unwrap();
	assert_eq!(bytes, network_graph.encode());
}

#[test]
fn write_for_routing_only_golden() {
	// One channel with both directions and one announced node with an address, all with stored
	// messages.
	let network_graph = create_network_graph();
	let secp_ctx = Secp256k1::new();
	let node_1_privkey = &SecretKey::from_slice(&[42; 32]).unwrap();
	let node_2_privkey = &SecretKey::from_slice(&[41; 32]).unwrap();
	let node_1 = NodeId::from_slice(&[0x11; 33]).unwrap();
	let node_2 = NodeId::from_slice(&[0x22; 33]).unwrap();
	let mut info = get_channel_info(node_1, node_2, 100);
	info.announcement_message =
		Some(get_signed_channel_announcement(|_| {}, node_1_privkey, node_2_privkey, &secp_ctx));
	let update = get_signed_channel_update(|_| {}, node_1_privkey, &secp_ctx);
	info.one_to_two.as_mut().unwrap().last_update_message = Some(update);
	let update = get_signed_channel_update(|u| u.channel_flags = 1, node_2_privkey, &secp_ctx);
	info.two_to_one.as_mut().unwrap().last_update_message = Some(update);
	network_graph.set_channel(42, info);
	let announcement = get_signed_node_announcement(
		|a| {
			a.node_id = node_1;
			a.features = NodeFeatures::empty();
			a.rgb = [1, 2, 3];
			a.alias = NodeAlias([4; 32]);
			a.addresses = vec![SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 9735 }];
		},
		node_1_privkey,
		&secp_ctx,
	);
	let announcement_info = NodeAnnouncementInfo::Relayed(announcement);
	network_graph.set_node_announcement(&node_1, Some(announcement_info));

	let channel_update_info = concat!(
		"34",                             // TLV stream length
		"000400000064",                   // last_update: 100
		"020101",                         // enabled: true
		"04020090",                       // cltv_expiry_delta: 144
		"060800000000000003e8",           // htlc_minimum_msat: 1_000
		"0809090000000005f5e100",         // htlc_maximum_msat: Some(100_000_000)
		"0a0d0c0004000003e8020400000064", // fees: 1_000 base, 100 proportional
		"0c0100",                         // last_update_message: None
	);
	let (node_one, node_two) = ("11".repeat(33), "22".repeat(33));
	let channel_info = [
		"d2",                   // TLV stream length
		"00020000",             // features: empty
		"010800000000000003e8", // announcement_received_time: 1_000
		"0221",                 // node_one
		&node_one,
		"043636", // one_to_two: Some
		channel_update_info,
		"0621", // node_two
		&node_two,
		"083636", // two_to_one: Some
		channel_update_info,
		"0a090900000000000f4240", // capacity_sats: Some(1_000_000)
		"0c0100",                 // announcement_message: None
	]
	.concat();
	let alias = "04".repeat(32);
	let node_announcement_info = [
		"33",           // TLV stream length
		"00020000",     // features: empty
		"020400000064", // last_update: 100
		"0403010203",   // rgb
		"0620",         // alias
		&alias,
		"0a00", // addresses: left out, and no announcement message (TLV 8)
	]
	.concat();
	let node_1_info = [
		&node_one, // node id
		"40",      // TLV stream length
		"0234",    // announcement_info
		&node_announcement_info,
		"0408000000000000002a", // channels: [42]
	]
	.concat();
	let node_2_info = [
		&node_two,              // node id
		"0a",                   // TLV stream length
		"0408000000000000002a", // channels: [42], and no announcement_info (TLV 2)
	]
	.concat();
	// Nodes are written in the graph's iteration order.
	let node_infos: String = network_graph
		.read_only()
		.nodes()
		.unordered_iter()
		.map(|(node_id, _)| if *node_id == node_1 { &node_1_info } else { &node_2_info })
		.map(String::as_str)
		.collect();
	let expected = [
		"0101",                                                             // version, min version
		"43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000", // testnet chain hash
		"0000000000000001",                                                 // channel count
		"000000000000002a",                                                 // SCID 42
		&channel_info,
		"0000000000000002", // node count
		&node_infos,
		"00", // TLV stream length, without last_rapid_gossip_sync_timestamp
	]
	.concat();

	let mut bytes = Vec::new();
	network_graph.write_for_routing_only(&mut bytes).unwrap();
	assert_eq!(bytes.as_hex().to_string(), expected);

	// Readable, and equal to the graph with only what routing needs.
	let logger = Arc::new(test_utils::TestLogger::new());
	let read_graph = NetworkGraph::read(&mut &<Vec<u8>>::from_hex(&expected).unwrap()[..], logger);
	assert_eq!(get_routing_view(&read_graph.unwrap()), get_routing_view(&network_graph));
}

/// Applies the changes `source` recorded to its replica `replica`, as a trusted source and its
/// replicas would: the source renders the current state of each changed channel and node, with
/// only what routing needs, and the replica applies the channel records and then the node records
/// as is. Then checks that applying them again, as overlapping updates do, changes nothing, which
/// needs `replica` to track its changes.
fn sync_graph<L: Logger>(source: &NetworkGraph<L>, replica: &NetworkGraph<L>) {
	let (channel_records, node_records) = {
		let graph = source.read_only();
		let changes = source.drain_changes();
		let channel_records: Vec<(u64, Option<Vec<u8>>)> = changes
			.channels
			.iter()
			.map(|scid| (*scid, graph.channel(*scid).map(|c| c.to_routing_only().encode())))
			.collect();
		// Nodes without channels don't exist, so they need no record.
		let node_records: Vec<(NodeId, Vec<u8>)> = changes
			.nodes
			.iter()
			.filter_map(|node_id| {
				let info = graph.node(node_id)?.announcement_info.as_ref();
				Some((*node_id, info.map(|a| a.to_routing_only()).encode()))
			})
			.collect();
		(channel_records, node_records)
	};

	let apply_records = || {
		for (scid, record) in &channel_records {
			match record {
				Some(record) => {
					let info = ChannelInfo::read(&mut &record[..]).unwrap();
					replica.set_channel(*scid, info);
				},
				None => replica.channel_failed_permanent(*scid),
			}
		}
		for (node_id, record) in &node_records {
			let info: Option<NodeAnnouncementInfo> = Readable::read(&mut &record[..]).unwrap();
			replica.set_node_announcement(node_id, info);
		}
	};
	apply_records();
	assert_eq!(get_routing_view(replica), get_routing_view(source));
	replica.test_node_counter_consistency();
	for (_, node) in replica.read_only().nodes().unordered_iter() {
		let announcement_info = node.announcement_info.as_ref();
		assert!(announcement_info.map_or(true, |a| a.addresses().is_empty()));
	}
	replica.drain_changes();
	apply_records();
	assert_eq!(replica.drain_changes(), GraphChanges::default());
}

#[test]
fn replicate_graph() {
	// Graph A is a trusted source's, kept up to date from gossip. Graph B is a replica: it starts
	// from A's routing-only snapshot, then applies A's changes.
	let secp_ctx = Secp256k1::new();
	let logger = test_utils::TestLogger::new();
	let chain_source = test_utils::TestChainSource::new(Network::Testnet);
	let mut graph_a = NetworkGraph::new(Network::Testnet, &logger);
	graph_a.enable_change_tracking();
	let gossip_sync = P2PGossipSync::new(&graph_a, Some(&chain_source), &logger);
	let script_pubkey = get_channel_script(&secp_ctx);
	let utxo = TxOut { value: Amount::from_sat(1_000_000), script_pubkey };
	*chain_source.utxo_ret.lock().unwrap() = UtxoResult::Sync(Ok(utxo));
	let privkeys: Vec<SecretKey> =
		(1..=7).map(|i| SecretKey::from_slice(&[i; 32]).unwrap()).collect();
	let nodes: Vec<NodeId> = privkeys.iter().map(|k| get_node_id(&secp_ctx, k)).collect();

	let get_announcement = |scid: u64, a: usize, b: usize| {
		get_signed_channel_announcement(
			|announcement| announcement.short_channel_id = scid,
			&privkeys[a],
			&privkeys[b],
			&secp_ctx,
		)
	};
	let announce = |scid: u64, a: usize, b: usize| {
		gossip_sync.handle_channel_announcement(None, &get_announcement(scid, a, b)).unwrap();
	};
	// Updates `direction` of the channel, from node `from`, with fees that vary with `timestamp`.
	let update = |scid: u64, from: usize, direction: u8, timestamp: u32| {
		let update = get_signed_channel_update(
			|u| {
				u.short_channel_id = scid;
				u.channel_flags = direction;
				u.timestamp = timestamp;
				u.fee_base_msat = timestamp;
			},
			&privkeys[from],
			&secp_ctx,
		);
		gossip_sync.handle_channel_update(None, &update).is_ok()
	};
	let announce_node = |node: usize, timestamp: u32| {
		let announcement = get_signed_node_announcement(
			|a| {
				a.timestamp = timestamp;
				a.rgb = [timestamp as u8; 3];
				a.addresses = vec![SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 9735 }];
			},
			&privkeys[node],
			&secp_ctx,
		);
		gossip_sync.handle_node_announcement(None, &announcement).is_ok()
	};

	announce(1, 0, 1);
	announce(2, 1, 2);
	graph_a.update_channel_from_announcement_no_lookup(&get_announcement(3, 2, 3)).unwrap();
	announce(4, 0, 2);
	for (scid, a, b) in [(1, 0, 1), (2, 1, 2), (3, 2, 3), (4, 0, 2)] {
		assert!(update(scid, a, 0, 1000) && update(scid, b, 1, 1000));
	}
	for node in 0..4 {
		assert!(announce_node(node, 1000));
	}
	let announcement_info = graph_a.read_only().node(&nodes[0]).unwrap().announcement_info.clone();
	assert!(!announcement_info.unwrap().addresses().is_empty());
	graph_a.drain_changes();
	let mut snapshot = Vec::new();
	graph_a.write_for_routing_only(&mut snapshot).unwrap();
	let mut graph_b = NetworkGraph::read(&mut &snapshot[..], &logger).unwrap();
	graph_b.enable_change_tracking();
	assert_eq!(get_routing_view(&graph_b), get_routing_view(&graph_a));

	// A new channel.
	announce(5, 4, 5);
	assert!(update(5, 4, 0, 1100) && update(5, 5, 1, 1100) && announce_node(4, 1100));
	sync_graph(&graph_a, &graph_b);

	// A reorg replaces channel 5, keeping node 4, whose only channel it is, but not its
	// announcement. An update older than the replaced channel's then applies.
	announce(5, 4, 6);
	assert!(update(5, 4, 0, 1050));
	// A UTXO lookup gives channel 3 its capacity. It's replaced, so it loses its directions, and
	// node 3, whose only channel it is, loses its announcement.
	announce(3, 2, 3);
	// Newer and older updates and node announcements.
	assert!(update(1, 0, 0, 1100) && !update(1, 1, 1, 900));
	assert!(announce_node(0, 1100) && !announce_node(1, 900));
	{
		let graph = graph_a.read_only();
		assert_eq!(graph.channel(3).unwrap().capacity_sats, Some(1_000_000));
		assert!(graph.node(&nodes[3]).unwrap().announcement_info.is_none());
		assert!(graph.node(&nodes[4]).unwrap().announcement_info.is_none());
	}
	sync_graph(&graph_a, &graph_b);

	// Node 6 gains a channel and loses another.
	announce(7, 6, 1);
	graph_a.channel_failed_permanent(5);
	sync_graph(&graph_a, &graph_b);

	// Node 3 loses its only channel, then gains one.
	graph_a.channel_failed_permanent(3);
	announce(8, 3, 5);
	assert!(update(8, 3, 0, 1200) && announce_node(3, 1200));
	sync_graph(&graph_a, &graph_b);

	// Node 1 and its channels fail.
	graph_a.node_failed_permanent(&PublicKey::from_secret_key(&secp_ctx, &privkeys[1]));
	sync_graph(&graph_a, &graph_b);

	// Pruning, far in the future, clears stale directions, and removes channels which miss one
	// and were announced long ago.
	let now: u32 = 4_000_000_000;
	let features = ChannelFeatures::empty();
	graph_a
		.add_channel_from_partial_announcement(
			9,
			None,
			now.into(),
			features.clone(),
			nodes[5],
			nodes[6],
		)
		.unwrap();
	graph_a
		.add_channel_from_partial_announcement(10, None, now.into(), features, nodes[0], nodes[5])
		.unwrap();
	assert!(update(9, 5, 0, now) && update(9, 6, 1, 1000));
	assert!(update(10, 0, 0, now) && update(10, 5, 1, now));
	sync_graph(&graph_a, &graph_b);
	graph_a.remove_stale_channels_and_tracking_with_time(now.into());
	let scids: Vec<u64> = get_routing_view(&graph_a).0.into_iter().map(|(scid, _)| scid).collect();
	assert_eq!(scids, vec![9, 10]);
	sync_graph(&graph_a, &graph_b);
}

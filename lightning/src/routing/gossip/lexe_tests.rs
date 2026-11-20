// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Lexe: tests for the fork's [`NetworkGraph`] additions: change tracking.

use crate::ln::msgs::{BaseMessageHandler, RoutingMessageHandler, MAX_VALUE_MSAT};
use crate::routing::gossip::tests::{
	create_gossip_sync, create_network_graph, get_channel_script, get_signed_channel_announcement,
	get_signed_channel_update, get_signed_node_announcement,
};
use crate::routing::gossip::{
	GraphChanges, NetworkGraph, NodeId, NodeInfo, P2PGossipSync,
	STALE_CHANNEL_UPDATE_AGE_LIMIT_SECS,
};
use crate::routing::utxo::{UtxoFuture, UtxoResult};
use crate::types::features::ChannelFeatures;
use crate::util::logger::Logger;
use crate::util::ser::{ReadableArgs, Writeable};
use crate::util::test_utils;
use crate::util::wakers::Notifier;

use bitcoin::amount::Amount;
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
